/*
 *  Collin's Dynamic Dalvik Instrumentation Toolkit for Android
 *  Collin Mulliner <collin[at]mulliner.org>
 *
 *  (c) 2012,2013
 *
 *  License: LGPL v2.1
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <sys/epoll.h>

#include <jni.h>
#include <stdlib.h>

#include "hook.h"
#include "dexstuff.h"
#include "dalvik_hook.h"
#include "base.h"

#undef log

#define log(...) \
        {FILE *fp = fopen("/data/local/tmp/ciphermon.log", "a+"); if (fp) {\
        fprintf(fp, __VA_ARGS__);\
        fclose(fp);}}

static struct hook_t eph;
static struct dexstuff_t d;

static int debug;

static void my_log(char *msg)
{
	log("%s", msg)
}
static void my_log2(char *msg)
{
	if (debug)
		log("%s", msg)
}

static struct dalvik_hook_t cp;

// helper function
void printString(JNIEnv *env, jobject str, char *l)
{
	const char *s = (*env)->GetStringUTFChars(env, str, 0);
	if (s) {
		log("%s%s\n", l, s)
		(*env)->ReleaseStringUTFChars(env, str, s); 
	}
}

// patches
static void* cp_dofinal(JNIEnv *env, jobject obj, jbyteArray ba)
{
	jbyteArray res;
	jvalue args[1];
	args[0].l = ba;
	log("before dalvik_prepare\n");
	dalvik_prepare(&d, &cp, env);
	res = (*env)->CallObjectMethodA(env, obj, cp.mid, args);
	log("success calling : %s\n", cp.method_name)
	dalvik_postcall(&d, &cp);
	log("after dalvik_postcall\n");
	return (void*)res;
}

void do_patch()
{
	log("do_patch()\n")

	dalvik_hook_setup(&cp, "Ljavax/crypto/Cipher;",  "doFinal",  "([B)[B", 2, cp_dofinal);
	dalvik_hook(&d, &cp);
}

static int my_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	int (*orig_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);
	orig_epoll_wait = (void*)eph.orig;
	// remove hook for epoll_wait
	hook_precall(&eph);

	// resolve symbols from DVM
	dexstuff_resolv_dvm(&d);
	// insert hooks
	do_patch();
	
	// call dump class (demo)
	dalvik_dump_class(&d, "Ljavax/crypto/Cipher;");
        
	// call original function
	int res = orig_epoll_wait(epfd, events, maxevents, timeout);    
	return res;
}

// set my_init as the entry point
void __attribute__ ((constructor)) my_init(void);

void my_init(void)
{
	log("libciphermon: started\n")
 
 	// set to 1 to turn on, this will be noisy
	debug = 0;

 	// set log function for  libbase (very important!)
	set_logfunction(my_log2);
	// set log function for libdalvikhook (very important!)
	dalvikhook_set_logfunction(my_log2);

	hook(&eph, getpid(), "libc.", "epoll_wait", my_epoll_wait, 0);
}
