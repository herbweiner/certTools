#-----------------------------------------------------------------------------
#	Makefile, Copyright (C) 2021 Herb Weiner. All rights reserved.
#	CC BY-SA 4.0: https://creativecommons.org/licenses/by-sa/4.0
#-----------------------------------------------------------------------------

all:	decodeCert deleteCert

decodeCert:	decodeCert.cc
	g++ -o decodeCert decodeCert.cc

deleteCert:	deleteCert.cc
	g++ -o deleteCert deleteCert.cc
