from .common import *

class OptionalMpls(Test):
    category = "PA2"
    description = "OptionalMpls"
    order = 2
    enabled = True
    test_order = ['test_near_pe', 'test_p', 'test_pe', 'test_all']


    def before(self):
        self.kill_clients()
        self.new_map()
        self.types = ['my', 'my', 'my', 'my', 'my', 'my', 'my', 'my', 'my', 'my', 'my']
        self.start_clients(count=11, mock=False, types=self.types)
        for i in range(0,11):
            self.clients[i].wait_for_start()
        self.map = Map(self.clients)


    def after(self):
        self.kill_clients()
        self.free_map()

    @grade(25)
    def test_near_pe(self):
        self.map.routers[2].client.write_io('send 192.168.200.2 vpn-A OpMpls')
        self.map.routers[2].mpls(-1, 2, '192.168.154.1', '192.168.200.2', 'OpMpls', initail_vpn=True, vpn_index=0)

        self.assert_true(self.map.routers[2].check_output(), message='Router 2 should print', end = False, grade=12)
        self.assert_true(self.map.routers[2].check_send_frames(1), message='Router 2 should send', end = False, grade=13)
        clear(self.map.routers, real = True)

    @grade(25)
    def test_p(self):
        self.map.routers[0].client.write_io('send 192.168.200.2 vpn-A OpMpls')
        self.map.routers[0].mpls(-1, 2, '192.168.144.1', '192.168.200.2', 'OpMpls', initail_vpn=True, vpn_index=0)

        self.assert_true(self.map.routers[0].check_output(), message='Router 0 should print', end = False, grade=12)
        self.assert_true(self.map.routers[0].check_send_frames(1), message='Router 0 should send', end = False, grade=13)
        clear(self.map.routers, real = True)

    @grade(25)
    def test_pe(self):
        self.map.routers[3].client.write_io('send 192.168.200.2 vpn-A OpMpls')
        self.map.routers[3].mpls(-1, 2, '192.168.200.4', '192.168.200.2', 'OpMpls', initail_vpn=True, vpn_index=0)

        self.assert_true(self.map.routers[3].check_output(), message='Router 3 should print', end = False, grade=12)
        self.assert_true(self.map.routers[3].check_send_frames(1), message='Router 3 should send', end = False, grade=13)
        clear(self.map.routers, real = True)

    @grade(25)
    def test_all(self):
        self.map.routers[1].client.write_io('send 192.168.200.2 vpn-B OpMpls')
        self.map.routers[1].mpls(-1, 4, '192.168.145.2', '192.168.200.2', 'OpMpls', initail_vpn=True, vpn_index=1)

        self.assert_true(self.map.routers[1].check_output(), message='Router 1 should print', end = False, grade=3)
        self.assert_true(self.map.routers[1].check_send_frames(1), message='Router 1 should send', end = False, grade=4)

        self.assert_true(self.map.routers[0].check_output(), message='Router 0 should print', end = False, grade=2)
        self.assert_true(self.map.routers[0].check_send_frames(1), message='Router 0 should send', end = False, grade=3)

        self.assert_true(self.map.routers[2].check_output(), message='Router 2 should print', end = False, grade=2)
        self.assert_true(self.map.routers[2].check_send_frames(1), message='Router 2 should send', end = False, grade=3)

        self.assert_true(self.map.routers[3].check_output(), message='Router 3 should print', end = False, grade=3)
        self.assert_true(self.map.routers[3].check_send_frames(2), message='Router 3 should send', end = False, grade=2)

        self.assert_true(self.map.routers[7].check_output(), message='Router 7 should print', end = False, grade=1.5)
        self.assert_true(self.map.routers[7].check_send_frames(0), message='Router 7 should send', end = False, grade=1.5)
        clear(self.map.routers, real = True)

