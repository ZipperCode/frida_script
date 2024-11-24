import threading

import frida
from frida_tools.reactor import Reactor


class Application:

    def __init__(self, pkg, script):
        self._pkg = pkg
        self._script = script
        self._event = threading.Event()
        self._reactor = Reactor(run_until_return=lambda reactor: self._event.wait() or None)

        # self._device = frida.get_local_device()
        self._device = frida.get_usb_device()
        self._sessions = set()

    def run(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        print(f"开始 {self._pkg}")
        self._device.on("spawn-added", lambda spawn: self._reactor.schedule(lambda: self._on_spawn_added(spawn)))
        self._device.on("spawn-removed", lambda spawn: self._reactor.schedule(lambda: self._on_spawn_remove(spawn)))
        self._device.on('child-added', lambda child: self._reactor.schedule(lambda: self._on_child_add(child)))
        self._device.on('child-removed', lambda child: self._reactor.schedule(lambda: self._on_child_removed(child)))
        self._device.on('process-crashed', lambda spawn: self._reactor.schedule(lambda: self._on_crash(spawn)))
        self._device.on('output',
                        lambda p, fd, child: self._reactor.schedule(lambda: self._on_output(p, fd, child)))
        self._device.on('uninjected', lambda spawn: self._reactor.schedule(lambda: self._on_uninjected(spawn)))
        self._device.on('lost', lambda spawn: self._reactor.schedule(lambda: self._on_lost(spawn)))
        self._device.enable_spawn_gating()
        pid = self._device.spawn([self._pkg])
        self._instrument(pid)

    def _instrument(self, pid):
        print("✔ instrument pid: ", pid)
        session = self._device.attach(pid)
        session.on("detached", lambda reason: self._reactor.schedule(lambda: self._on_detached(pid, session, reason)))
        print("✔ create_script()")
        with open(self._script) as f:
            script = session.create_script(f.read())
        script.on("message", lambda message, data: self._reactor.schedule(lambda: self._on_message(pid, message)))
        print("✔ load()")
        script.load()
        print("✔ resume(pid={})".format(pid))
        self._device.resume(pid)
        self._sessions.add(session)

    @staticmethod
    def on_spawned(spawn):
        print("进程spawn: ", spawn)

    @staticmethod
    def _on_crash(spawn):
        print("spawn crash: ", spawn)

    @staticmethod
    def _on_child_add(child):
        print("child add: ", child)

    @staticmethod
    def _on_child_removed(child):
        print("child remove: ", child)

    @staticmethod
    def _on_output(pid, fd, child):
        print(f"output: pid={pid}, fd={fd}, child={child}")

    @staticmethod
    def _on_uninjected(spawn):
        print("unjected: ", spawn)

    @staticmethod
    def _on_lost(spawn):
        print("lost: ", spawn)

    def _on_spawn_added(self, spawn):
        if not spawn.identifier.startswith(self._pkg):
            return
        pid = spawn.pid
        print("✔ spawn add: ", spawn)
        self._instrument(pid)

    def _on_spawn_remove(self, spawn):
        print("spawn_remove: ", spawn)

    @staticmethod
    def _on_message(pid, message):
        if message['type'] == 'send':
            print("⚡ message: pid={}, payload={}".format(pid, message['payload']))
        else:
            print("⚡ message: pid={}, payload={}".format(pid, message))

    def _on_detached(self, pid, session, reason):
        print("⚡ detached: pid={}, reason='{}'".format(pid, reason))
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._event.set()


if __name__ == '__main__':
    pkg = "com.eg.android.AlipayGphone"
    js = "alipay.js"
    app = Application(pkg, js)
    app.run()
