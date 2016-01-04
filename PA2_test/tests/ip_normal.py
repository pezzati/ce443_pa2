from .common import *

class IpNormal(Test):
    category = "PA2"
    description = "ip_normal"
    order = 1
    enabled = True
    test_order = ['test_neighbor', 'test_direct', 'test_indirect']


    def before(self):
        
        self.kill_clients()
        self.new_map()
        self.types = []
        for i in xrange(11):
            self.types.append('my')
        self.start_clients(count=11, mock=False, types=self.types)
        for i in range(0,11):
            self.clients[i].wait_for_start()
        self.map = Map(self.clients)


    def after(self):
        self.kill_clients()
        self.free_map()

    
    @grade(16)
    def test_neighbor(self):
        print('test_neighbor')
        self.map.routers[1].client.write_io('send 192.168.145.1 N/A hellow')
        self.map.routers[1].send_ip('', '192.168.145.1', 5000, 3000, -1, 'hellow')

        self.assert_true(self.map.routers[1].check_output(), message='test_neighbor Router 1 should print', end = False, grade=3.25)
        self.assert_true(self.map.routers[1].check_send_frames(1), message='test_neighbor Router 1 should send', end = False, grade=3.25)
        self.assert_true(self.map.routers[0].check_output(), message='test_neighbor Router 0 should print', end = False, grade=6.25)
        self.assert_true(self.map.routers[0].check_send_frames(0), message='test_neighbor Router 0 should send', end = True, grade=3.25)
        clear(self.map.routers, real = True)

    @grade(42)
    def test_direct(self):
        print('test_direct')
        self.map.routers[4].client.write_io('send 192.168.154.2 N/A bye')
        self.map.routers[4].send_ip('', '192.168.154.2', 5000, 3000, -1, 'bye')

        self.assert_true(self.map.routers[4].check_output(), message='Router 4 should print', end = False, grade=3.25)
        self.assert_true(self.map.routers[4].check_send_frames(0), message='Router 4 should send', end = False, grade=3.25)
        self.assert_true(self.map.routers[0].check_output(), message='Router 0 should print', end = False, grade=6.5)
        self.assert_true(self.map.routers[0].check_send_frames(2), message='Router 0 should send on iface2', end = False, grade=3.25)

        self.assert_true(self.map.routers[0].check_send_frames(1), message='Router 0 should send on iface1', end = False, grade=3.25)
        self.assert_true(self.map.routers[2].check_output(), message='Router 2 should print', end = False, grade=6.5)
        self.assert_true(self.map.routers[2].check_all_send_frames(), message='Router 2 should send', end = False, grade=6.5)

        self.assert_true(self.map.routers[3].check_output(), message='Router 3 should print', end = False, grade=6.25)
        self.assert_true(self.map.routers[3].check_send_frames(0), message='Router 3 should send', end = False, grade=3.25)
        clear(self.map.routers, real = True)

    @grade(42)
    def test_indirect(self):
        print('test_indirect')
        self.map.routers[5].client.write_io('send 192.168.154.1 N/A bye')
        self.map.routers[5].send_ip('', '192.168.154.1', 5000, 3000, -1, 'bye')

        self.assert_true(self.map.routers[5].check_output(), message='Router 5 should print', end = False, grade=3.25)
        self.assert_true(self.map.routers[5].check_send_frames(0), message='Router 5 should send', end = False, grade=3.25)
        self.assert_true(self.map.routers[1].check_output(), message='Router 1 should print', end = False, grade=6.5)
        self.assert_true(self.map.routers[1].check_send_frames(0), message='Router 1 should send', end = False, grade=3.25)
        self.assert_true(self.map.routers[1].check_send_frames(1), message='Router 1 should send', end = False, grade=3.25)

        self.assert_true(self.map.routers[0].check_output(), message='Router 0 should print', end = False, grade=6.5)
        self.assert_true(self.map.routers[0].check_send_frames(0), message='Router 0 should send', end = False, grade=3.25)
        self.assert_true(self.map.routers[0].check_send_frames(1), message='Router 0 should send', end = False, grade=3.25)

        self.assert_true(self.map.routers[2].check_output(), message='Router 2 should print', end = False, grade=6.25)
        self.assert_true(self.map.routers[2].check_send_frames(0), message='Router 2 should send', end = False, grade=3.25)
        clear(self.map.routers, real = True)

