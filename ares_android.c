/* Copyright (C) 2017 by John Schember <john@nachtimwald.com>
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */
#if defined(ANDROID) || defined(__ANDROID__)

#include <jni.h>

#include "ares_setup.h"
#include "ares.h"
#include "ares_android.h"
#include "ares_private.h"

static JavaVM *android_jvm = NULL;
static jobject android_connectivity_manager = NULL;

static jclass jni_get_class(JNIEnv *env, const char *path)
{
  jclass cls = NULL;

  if (env == NULL || path == NULL || *path == '\0')
    return NULL;

  cls = (*env)->FindClass(env, path);
  if ((*env)->ExceptionOccurred(env)) {
    (*env)->ExceptionClear(env);
    return NULL;
  }
  return cls;
}

static jmethodID jni_get_method_id(JNIEnv *env, jclass cls,
                                   const char *func_name, const char *signature)
{
  jmethodID mid = NULL;

  if (env == NULL || cls == NULL || func_name == NULL || *func_name == '\0' ||
          signature == NULL || *signature == '\0')
  {
    return NULL;
  }

  mid = (*env)->GetMethodID(env, cls, func_name, signature);
  if ((*env)->ExceptionOccurred(env))
  {
    (*env)->ExceptionClear(env);
    return NULL;
  }

  return mid;
}

void ares_library_init_jvm(JavaVM *jvm)
{
  android_jvm = jvm;
}

int ares_library_init_android(jobject connectivity_manager)
{
  JNIEnv *env = NULL;
  int need_detatch = 0;
  int res;

  if (android_jvm == NULL)
    return ARES_ENOTINITIALIZED;

  res = (*android_jvm)->GetEnv(android_jvm, (void **)&env, JNI_VERSION_1_6);
  if (res == JNI_EDETACHED)
  {
    env = NULL;
    res = (*android_jvm)->AttachCurrentThread(android_jvm, &env, NULL);
    need_detatch = 1;
  }
  if (res != JNI_OK || env == NULL)
    return ARES_ENOTINITIALIZED;

  android_connectivity_manager = (*env)->NewGlobalRef(env, connectivity_manager);

  if (need_detatch)
    (*android_jvm)->DetachCurrentThread(android_jvm);

  return ARES_SUCCESS;
}

int ares_library_android_initialized(void)
{
  if (android_jvm == NULL || android_connectivity_manager == NULL)
    return ARES_ENOTINITIALIZED;
  return ARES_SUCCESS;
}

void ares_library_cleanup_android(void)
{
  JNIEnv *env = NULL;
  int need_detatch = 0;
  int res;

  if (android_jvm == NULL || android_connectivity_manager == NULL)
    return;

  res = (*android_jvm)->GetEnv(android_jvm, (void **)&env, JNI_VERSION_1_6);
  if (res == JNI_EDETACHED)
  {
    env = NULL;
    res = (*android_jvm)->AttachCurrentThread(android_jvm, &env, NULL);
    need_detatch = 1;
  }
  if (res != JNI_OK || env == NULL)
    return;

  (*env)->DeleteGlobalRef(env, android_connectivity_manager);
  android_connectivity_manager = NULL;

  if (need_detatch)
    (*android_jvm)->DetachCurrentThread(android_jvm);
}

char **ares_get_android_server_list(size_t max_servers,
                                    size_t *num_servers)
{
  JNIEnv *env = NULL;
  jobject active_network = NULL;
  jobject link_properties = NULL;
  jobject server_list = NULL;
  jobject server = NULL;
  jstring str;
  jclass obj_cls;
  jmethodID obj_mid;
  jclass list_cls;
  jmethodID list_mid;
  jint nserv;
  const char *ch_server_address;
  int res;
  size_t i;
  char **dns_list = NULL;
  int need_detatch = 0;

  if (android_jvm == NULL || android_connectivity_manager == NULL ||
          max_servers == 0 || num_servers == NULL)
  {
    return NULL;
  }

  res = (*android_jvm)->GetEnv(android_jvm, (void **)&env, JNI_VERSION_1_6);
  if (res == JNI_EDETACHED)
  {
    env = NULL;
    res = (*android_jvm)->AttachCurrentThread(android_jvm, &env, NULL);
    need_detatch = 1;
  }
  if (res != JNI_OK || env == NULL)
    goto done;

  /* JNI below is equivalent to this Java code.
     import android.content.Context;
     import android.net.ConnectivityManager;
     import android.net.LinkProperties;
     import android.net.Network;
     import java.net.InetAddress;
     import java.util.List;

     ConnectivityManager cm = (ConnectivityManager)this.getApplicationContext()
       .getSystemService(Context.CONNECTIVITY_SERVICE);
     Network an = cm.getActiveNetwork();
     LinkProperties lp = cm.getLinkProperties(an);
     List<InetAddress> dns = lp.getDnsServers();
     for (InetAddress ia: dns) {
       String ha = ia.getHostAddress();
     }

     Note: The JNI ConnectivityManager object was previously initialized in
           ares_library_init_android.
   */

  /* ConnectivityManager in API 1. */
  obj_cls = jni_get_class(env, "android/net/ConnectivityManager");
  if (obj_cls == NULL)
    goto done;
  /* ConnectivityManager.getActiveNetwork in API 23. */
  obj_mid = jni_get_method_id(env, obj_cls, "getActiveNetwork",
                              "()Landroid/net/Network;");
  if (obj_mid == NULL)
    goto done;
  active_network = (*env)->CallObjectMethod(env, android_connectivity_manager,
                                            obj_mid);
  if (active_network == NULL)
    goto done;

  /* ConnectivityManager.getLinkProperties in API 21. */
  obj_mid = jni_get_method_id(env, obj_cls, "getLinkProperties",
            "(Landroid/net/Network;)Landroid/net/LinkProperties;");
  if (obj_mid == NULL)
    goto done;
  link_properties = (*env)->CallObjectMethod(env, android_connectivity_manager,
                                             obj_mid, active_network);
  if (link_properties == NULL)
    goto done;

  /* LinkProperties in API 21. */
  obj_cls = jni_get_class(env, "android/net/LinkProperties");
  if (obj_cls == NULL)
    goto done;
  /* getDnsServers in API 21. */
  obj_mid = jni_get_method_id(env, obj_cls, "getDnsServers",
                              "()Ljava/util/List;");
  if (obj_mid == NULL)
    goto done;
  server_list = (*env)->CallObjectMethod(env, link_properties, obj_mid);
  if (server_list == NULL)
    goto done;

  list_cls = jni_get_class(env, "java/util/List");
  if (list_cls == NULL)
    goto done;
  list_mid = jni_get_method_id(env, list_cls, "size", "()I");
  if (list_mid == NULL)
    goto done;
  nserv = (*env)->CallIntMethod(env, server_list, list_mid);
  if (nserv > (jint)max_servers)
    nserv = (jint)max_servers;
  if (nserv <= 0)
    goto done;
  *num_servers = (size_t)nserv;
  list_mid = jni_get_method_id(env, list_cls, "get", "(I)Ljava/lang/Object;");
  if (list_mid == NULL)
    goto done;

  obj_cls = jni_get_class(env, "java/net/InetAddress");
  if (obj_cls == NULL)
    goto done;
  obj_mid = jni_get_method_id(env, obj_cls, "getHostAddress",
                              "()Ljava/lang/String;");
  if (obj_mid == NULL)
    goto done;
  dns_list = ares_malloc(sizeof(*dns_list)*(*num_servers));
  for (i=0; i<*num_servers; i++)
  {
    server = (*env)->CallObjectMethod(env, server_list, list_mid, (jint)i);
    dns_list[i] = ares_malloc(64);
    dns_list[i][0] = 0;
    if (server == NULL)
    {
      continue;
    }
    str = (*env)->CallObjectMethod(env, server, obj_mid);
    ch_server_address = (*env)->GetStringUTFChars(env, str, 0);
    strncpy(dns_list[i], ch_server_address, 64);
    (*env)->ReleaseStringUTFChars(env, str, ch_server_address);
  }

done:
  if ((*env)->ExceptionOccurred(env))
    (*env)->ExceptionClear(env);

  if (server_list != NULL)
    (*env)->DeleteLocalRef(env, server_list);
  if (link_properties != NULL)
    (*env)->DeleteLocalRef(env, link_properties);
  if (active_network != NULL)
    (*env)->DeleteLocalRef(env, active_network);

  if (need_detatch)
    (*android_jvm)->DetachCurrentThread(android_jvm);
  return dns_list;
}

#endif
