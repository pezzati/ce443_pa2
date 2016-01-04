from .common import *

class MplsTest(Test):
    category = "PA2"
    description = "MplsTest"
    order = 2
    enabled = True
    test_order = ['test_mpls_full']


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


    @grade(100)
    def test_mpls_full(self):
        self.map.routers[6].client.write_io('send 192.168.202.2 N/A mplsMsg')
        self.map.routers[6].send_ip('', '192.168.202.2', 5000, 3000, -1, 'mplsMsg')
        
        self.assert_true(self.map.routers[6].check_output(), message='Router 6 should print', end = False, grade=3.5)
        self.assert_true(self.map.routers[6].check_send_frames(0), message='Router 6 should send', end = False, grade=4.5)

        self.assert_true(self.map.routers[3].check_send_frames(1), message='Router 3 should send at iface1', end = False, grade=3.5)
        self.assert_true(self.map.routers[3].check_output(), message='Router 3 should print', end = False, grade=6.5)
        self.assert_true(self.map.routers[3].check_send_frames(0), message='Router 3 should send at iface0', end = False, grade=5)
        
        self.assert_true(self.map.routers[2].check_send_frames(1), message='Router 2 should send at iface1', end = False, grade=5)
        self.assert_true(self.map.routers[2].check_output(), message='Router 2 should print', end = False, grade=8)
        self.assert_true(self.map.routers[2].check_send_frames(0), message='Router 2 should send at iface0', end = False, grade=5)

        self.assert_true(self.map.routers[0].check_send_frames(1), message='Router 0 should send at iface1', end = False, grade=5)
        self.assert_true(self.map.routers[0].check_output(), message='Router 0 should print', end = False, grade=8)
        self.assert_true(self.map.routers[0].check_send_frames(0), message='Router 0 should send at iface0', end = False, grade=5)

        self.assert_true(self.map.routers[1].check_send_frames(1), message='Router 1 should send at iface1', end = False, grade=5)
        self.assert_true(self.map.routers[1].check_output(), message='Router 1 should print', end = False, grade=8)
        self.assert_true(self.map.routers[1].check_send_frames(0), message='Router 1 should send at iface0', end = False, grade=5)

        self.assert_true(self.map.routers[5].check_send_frames(0), message='Router 5 should send at iface1', end = False, grade=5)
        self.assert_true(self.map.routers[5].check_output(), message='Router 5 should print', end = False, grade=6.5)
        self.assert_true(self.map.routers[5].check_send_frames(1), message='Router 5 should send at iface0', end = False, grade=3.5)
        
        self.assert_true(self.map.routers[10].check_output(), message='Router 10 should print', end = False, grade=4.5)
        self.assert_true(self.map.routers[10].check_send_frames(0), message='Router 10 should send', end = False, grade=3.5)
        
        clear(self.map.routers, real = True)

        
        
        

        clear(self.map.routers, real = True)