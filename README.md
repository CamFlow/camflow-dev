#CamFlow Dev

##Building
* make prepare
* make config
 * select relevant modules in security
* make compile
 * be patient
 * it may ask for sudo password mid-way
* make install
 * continue to be patient
 * it may ask for sudo password


##TODO
* Look at NetLabel, XFRM and IPSEC for labelled packet (may not be able to get what we want).
* Investigate audit data captured.
* Look at Coccinelle for patching /security/security.c and .h files.
* Finish/build command line tool(s) to manage the module.
