#include "config.h"

#include <epan/packet.h>

#include <cstdlib>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

#define SRC_MTP_PORT 7000
#define DST_MTP_PORT 8000

void mtp_register(){
	mtp = proto_register_protocol(
		"MTP Protocol", /* name */
		"MTP",
		"mtp"
	);
}