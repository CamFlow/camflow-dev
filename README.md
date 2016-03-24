# CamFlow

##Building
* make prepare
* make config
 * select relevant modules in security
* make compile
 * be patient
 * it will ask for root password mid-way
* make install
 * continue to be patient
 * it will ask for root password


##TODO
* Look at NetLabel, XFRM and IPSEC for labelled packet (may not be able to get what we want).
* Investigate audit data captured.
* Look at Coccinelle for patching /security/security.c and .h files.
