from .common import *

class MplsDetailedTest(Test):
    category = "PA2"
    description = "MplsDetailesTest"
    order = 2
    enabled = True
    test_order = ['test_detect_vpn_interface',
                    'test_switch_label',
                    'test_pop_send',
                    'test_pop_vpn']


    def before(self):
        self.kill_clients()
        self.new_map()
        self.types = ['cf', 'my', 'cf', 'my', 'my', 'cf', 'cf', 'my', 'my', 'my', 'cf']
        self.start_clients(count=11, mock=False, types=self.types)
        for i in range(0,11):
            self.clients[i].wait_for_start()
        self.map = Map(self.clients)


    def after(self):
        self.kill_clients()
        self.free_map()


    @grade(25)
    def test_detect_vpn_interface(self):
        self.map.routers[6].client.write_io('send 192.168.202.2 N/A mplsMsg')
        self.map.routers[6].send_ip('', '192.168.202.2', 5000, 3000, -1, 'mplsMsg')
        
        self.assert_true(self.map.routers[3].check_output(), message='Router 3 should print', end = False, grade=10)
        self.assert_true(self.map.routers[3].check_send_frames(0), message='Router 3 should send', end = False, grade=15)
        clear(self.map.routers, real = True)

    @grade(25)
    def test_switch_label(self):
        self.map.routers[5].client.write_io('send 192.168.200.2 vpn-A mplsMsg')
        self.map.routers[1].mpls(6, 2, '192.168.155.2', '192.168.200.2', 'mplsMsg')

        self.assert_true(self.map.routers[1].check_output(), message='Router 1 should print', end = False, grade=10)
        self.assert_true(self.map.routers[1].check_send_frames(1), message='Router 1 should send', end = False, grade=15)
        clear(self.map.routers, real = True)

    @grade(25)
    def test_pop_send(self):
        self.map.routers[0].client.write_io('send 192.168.202.2 vpn-A mplsMsg')
        self.map.routers[1].mpls(7, 3, '192.168.145.1', '192.168.202.2', 'mplsMsg')

        self.assert_true(self.map.routers[1].check_output(), message='Router 1 should print', end = False, grade=10)
        self.assert_true(self.map.routers[1].check_send_frames(0), message='Router 1 should send', end = False, grade=15)
        clear(self.map.routers, real = True)

    @grade(25)
    def test_pop_vpn(self):
        self.map.routers[2].client.write_io('send 192.168.200.2 vpn-A mplsMsg')
        self.map.routers[3].mpls(-1, 2, '192.168.154.1', '192.168.200.2', 'mplsMsg')

        self.assert_true(self.map.routers[3].check_output(), message='Router 1 should print', end = False, grade=10)
        self.assert_true(self.map.routers[3].check_send_frames(1), message='Router 1 should send', end = False, grade=15)
        clear(self.map.routers, real = True)
