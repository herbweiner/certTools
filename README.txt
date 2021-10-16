certTools, Copyright (C) 2021 Herb Weiner. All rights reserved.
CC BY-SA 4.0: https://creativecommons.org/licenses/by-sa/4.0

These tools facilitate examining and editing certicate chains,
such as those used by Let's Encrypt (https://letsencrypt.org).

These command line tools have been developed and tested on Mac,
and will probably work fine on Linux or Unix systems. Porting
to Windows is left as an exercise for the reader.

To view all options:
	decodeCert -h
	deleteCert -h

For example, to delete the "DST Root CA X3" from multiple fullchain.pem files:
	deleteCert -i "DST Root CA X3" */fullchain.pem

To see what will be done without actually changing any files, run in Test mode:
	deleteCert -t -i "DST Root CA X3" */fullchain.pem
