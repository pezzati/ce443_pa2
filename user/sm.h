//                   In the name of GOD
/**
 * Partov is a simulation engine, supporting emulation as well,
 * making it possible to create virtual networks.
 *  
 * Copyright © 2009-2015 Behnam Momeni.
 * 
 * This file is part of the Partov.
 * 
 * Partov is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Partov is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Partov.  If not, see <http://www.gnu.org/licenses/>.
 *  
 */

#ifndef _S_M_H_
#define _S_M_H_

#include "machine.h"
#include <cstdlib>
#include <iostream>
#include <string.h>
#include <stdio.h>

using namespace std;

class SimulatedMachine : public Machine {
public:
	SimulatedMachine (const ClientFramework *cf, int count);
	virtual ~SimulatedMachine ();

	virtual void initialize ();
	virtual void run ();
	virtual void processFrame (Frame frame, int ifaceIndex);
	
	static void parseArguments (int argc, char *argv[]);

	void sendARPReq( int ifaceIndex, uint32_t egress_ip);
	Frame* createMPLS_IP_packet(uint32_t destIp, uint8_t *destMac, int ifaceIndex, int vpn_label, int tunnel_label, string msg);
	void handleVPNlabel(uint8_t *data, int length , int ifaceIndex);
	void forwardMPLSPacket(uint8_t *data, int length, struct label_routing_node *target_router);
	void sendMPLSPacket(uint32_t destIp, uint8_t *destMac, int ifaceIndex, string msg, int vpn_label, int tunnel_label);
	void sendPacket(uint32_t destIp, uint8_t *destMac, int ifaceIndex, string msg);
	void sendARPRes(uint8_t *data, int ifaceIndex);
};

#endif /* sm.h */

