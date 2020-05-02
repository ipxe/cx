/*
 * Copyright (C) 2020 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders of this
 * program give you permission to combine this program with code
 * included in the standard release of OpenSSL (or modified versions
 * of such code, with unchanged license).  You may copy and distribute
 * such a system following the terms of the GNU GPL for this program
 * and the licenses of the other code concerned.
 */

/******************************************************************************
 *
 * Java Native Interface
 *
 ******************************************************************************
 */

#include <stdint.h>
#include <endian.h>
#include <cx.h>
#include <cx/generator.h>
#include <cx/jni.h>
#include "debug.h"

/** Required JNI version */
#define CX_JNI_VERSION JNI_VERSION_1_6

/** org.ipxe.cx.CxJni */
static struct {
	/** Class */
	jclass clazz;
} cxjni;

/** java.util.UUID */
static struct {
	/** Class */
	jclass clazz;
	/** Constructor */
	jmethodID constructor;
} juuid;

/******************************************************************************
 *
 * Helper functions
 *
 ******************************************************************************
 */

/**
 * Get byte array data
 *
 * @v env		JNI environment
 * @v bytes		Byte array
 * @v len		Length of byte array to fill in (or NULL)
 * @ret data		Byte array data (or NULL on error)
 *
 * The caller is responsible for calling bytes_release().
 */
static inline void * bytes_get ( JNIEnv *env, jbyteArray bytes, size_t *len ) {
	void *data;

	/* Get (potentially a copy of) byte array data */
	data = (*env)->GetByteArrayElements ( env, bytes, NULL );
	if ( ! data )
		return NULL;

	/* Get length of byte array, if requested */
	if ( len )
		*len = (*env)->GetArrayLength ( env, bytes );

	return data;
}

/**
 * Release byte array data
 *
 * @v env		JNI environment
 * @v bytes		Byte array
 * @v data		Byte array data
 */
static inline void bytes_release ( JNIEnv *env, jbyteArray bytes,
				   void *data ) {

	/* Release and discard byte array data */
	(*env)->ReleaseByteArrayElements ( env, bytes, data, JNI_ABORT );
}

/******************************************************************************
 *
 * Generators
 *
 ******************************************************************************
 */

/**
 * Get generator seed length
 *
 * @v env		JNI environment
 * @v clazz		Java class
 * @v type		Generator type
 * @ret len		Seed length (or 0 on error)
 */
static jint JNICALL genSeedLen ( JNIEnv *env, jclass clazz, jint type ) {

	( void ) env;
	( void ) clazz;

	return cx_gen_seed_len ( type );
}

/**
 * Get generator maximum number of iterations
 *
 * @v env		JNI environment
 * @v clazz		Java class
 * @v type		Generator type
 * @ret max		Maximum number of iterations (or 0 on error)
 */
static jint JNICALL genMaxIterations ( JNIEnv *env, jclass clazz, jint type ) {

	( void ) env;
	( void ) clazz;

	return cx_gen_max_iterations ( type );
}

/**
 * Instantiate generator
 *
 * @v env		JNI environment
 * @v clazz		Java class
 * @v type		Generator type
 * @v seed		Seed value
 * @ret handle		Generator handle (or NULL on error)
 */
static jlong JNICALL genInstantiate ( JNIEnv *env, jclass clazz, jint type,
				      jbyteArray seed ) {
	struct cx_generator *gen;
	void *seedbuf;
	size_t seedlen;

	( void ) clazz;

	/* Get seed value */
	seedbuf = bytes_get ( env, seed, &seedlen );
	if ( ! seedbuf )
		goto err_seed;

	/* Instantiate generator */
	gen = cx_gen_instantiate ( type, seedbuf, seedlen );
	if ( ! gen )
		goto err_instantiate;

	/* Free seed value */
	bytes_release ( env, seed, seedbuf );

	return (intptr_t) gen;

	cx_gen_uninstantiate ( gen );
 err_instantiate:
	bytes_release ( env, seed, seedbuf );
 err_seed:
	return 0;
}

/**
 * Iterate generator
 *
 * @v env		JNI environment
 * @v clazz		Java class
 * @v handle		Generator handle
 * @ret id		Contact ID (or NULL on error)
 */
static jobject JNICALL genIterate ( JNIEnv *env, jclass clazz, jlong handle ) {
	struct cx_generator *gen = ( void * ) handle;
	union {
		uint64_t half[2];
		struct cx_contact_id id;
	} u;
	jobject uuid;

	( void ) clazz;

	/* Sanity check */
	_Static_assert ( sizeof ( u.half ) == sizeof ( u.id ),
			 "cx_contact_id layout mismatch" );

	/* Iterate generator */
	if ( ! cx_gen_iterate ( gen, &u.id ) )
		return NULL;

	/* Construct UUID */
	uuid = (*env)->NewObject ( env, juuid.clazz, juuid.constructor,
				   ( ( jlong ) be64toh ( u.half[0] ) ),
				   ( ( jlong ) be64toh ( u.half[1] ) ) );
	if ( ! uuid ) {
		cx_gen_invalidate ( gen );
		return NULL;
	}

	return uuid;
}

/**
 * Instantiate generator
 *
 * @v env		JNI environment
 * @v clazz		Java class
 * @v type		Generator type
 * @v seed		Seed value
 * @ret handle		Generator handle (or NULL on error)
 */
static void JNICALL genUninstantiate ( JNIEnv *env, jclass clazz,
					jlong handle ) {
	struct cx_generator *gen = ( void * ) handle;

	( void ) env;
	( void ) clazz;

	/* Uninstantiate generator */
	cx_gen_uninstantiate ( gen );
}

/******************************************************************************
 *
 * Registration
 *
 ******************************************************************************
 */

/** A JNI required method */
struct jni_required_method {
	/** Method name */
	const char *name;
	/** Method signature */
	const char *signature;
	/** Method ID */
	jmethodID *id;
};

/** A JNI required method set */
struct jni_required_methods {
	/** Methods */
	const struct jni_required_method *methods;
	/** Number of methods */
	unsigned int count;
};

/** A JNI native method set */
struct jni_native_methods {
	/** Native methods */
	const JNINativeMethod *methods;
	/** Number of methods */
	unsigned int count;
};

/** Declare a method set */
#define JNI_METHODS( name ) { name, sizeof ( name ) / sizeof ( name[0] ) }

/** A JNI class descriptor */
struct jni_class_descriptor {
	/** Class name */
	const char *name;
	/** Class pointer */
	jclass *clazz;
	/** Native methods */
	struct jni_native_methods native;
	/** Required methods */
	struct jni_required_methods required;
};

/** org.ipxe.cx.CxJni native methods */
static const JNINativeMethod cxjni_native_methods[] = {
	{ "genSeedLen", "(I)I", genSeedLen },
	{ "genMaxIterations", "(I)I", genMaxIterations },
	{ "genInstantiate", "(I[B)J", genInstantiate },
	{ "genIterate", "(J)Ljava/util/UUID;", genIterate },
	{ "genUninstantiate", "(J)V", genUninstantiate },
};

/** util.java.UUID methods */
static const struct jni_required_method uuid_methods[] = {
	{ "<init>", "(JJ)V", &juuid.constructor },
};

/** Required JNI classes */
static const struct jni_class_descriptor jni_classes[] = {
	{
		.name = "org/ipxe/cx/CxJni",
		.clazz = &cxjni.clazz,
		.native = JNI_METHODS ( cxjni_native_methods ),
	},
	{
		.name = "java/util/UUID",
		.clazz = &juuid.clazz,
		.required = JNI_METHODS ( uuid_methods ),
	},
};

/**
 * Register a JNI class
 *
 * @v env		JNI environment
 * @v desc		JNI class descriptor
 * @ret ok		Success indicator
 */
static int jni_register ( JNIEnv *env,
			  const struct jni_class_descriptor *desc ) {
	const struct jni_required_method *required;
	jclass clazz;
	unsigned int i;
	jint rc;

	/* Find class */
	clazz = (*env)->FindClass ( env, desc->name );
	if ( ! clazz ) {
		DBG ( "JNI could not find class %s\n", desc->name );
		goto err_find;
	}

	/* Get new global reference to class */
	*(desc->clazz) = (*env)->NewGlobalRef ( env, clazz );
	if ( ! *(desc->clazz) ) {
		DBG ( "JNI could not get global reference to %s\n",
		      desc->name );
		goto err_global;
	}

	/* Register any native methods */
	if ( desc->native.count &&
	     ( ( rc = (*env)->RegisterNatives ( env, *(desc->clazz),
						desc->native.methods,
						desc->native.count ) ) != 0 )){
		DBG ( "JNI could not register native methods for %s: error "
		      "%d\n", desc->name, rc );
		goto err_native;
	}

	/* Get IDs for any required methods */
	for ( i = 0 ; i < desc->required.count ; i++ ) {
		required = &desc->required.methods[i];
		*(required->id) = (*env)->GetMethodID ( env, *(desc->clazz),
							required->name,
							required->signature );
		if ( ! *(required->id) ) {
			DBG ( "JNI could not get %s method %s%s\n", desc->name,
			      required->name, required->signature );
			goto err_required;
		}
	}

	/* Drop local reference */
	(*env)->DeleteLocalRef ( env, clazz );

	return 1;

 err_required:
	if ( desc->native.methods )
		(*env)->UnregisterNatives ( env, *(desc->clazz) );
 err_native:
	(*env)->DeleteGlobalRef ( env, *(desc->clazz) );
 err_global:
	(*env)->DeleteLocalRef ( env, clazz );
 err_find:
	return 0;
}

/**
 * Unregister a JNI class
 *
 * @v env		JNI environment
 * @v desc		JNI class descriptor
 */
static void jni_unregister ( JNIEnv *env,
			     const struct jni_class_descriptor *desc ) {

	/* Unregister any native methods */
	if ( desc->native.count )
		(*env)->UnregisterNatives ( env, *(desc->clazz) );

	/* Drop global reference */
	(*env)->DeleteGlobalRef ( env, *(desc->clazz) );
}

/**
 * Register all JNI classes
 *
 * @v env		JNI environment
 * @ret ok		Success indicator
 */
static int jni_register_all ( JNIEnv *env ) {
	int i;

	/* Register all classes */
	for ( i = 0 ; i < ( ( int ) ( sizeof ( jni_classes ) /
				      sizeof ( jni_classes[0] ) ) ) ; i++ ) {
		if ( ! jni_register ( env, &jni_classes[i] ) )
			goto err_register;
	}

	return 1;

 err_register:
	for ( i-- ; i >= 0 ; i-- )
		jni_unregister ( env, &jni_classes[i] );
	return 0;
}

/**
 * Unregister all JNI clases
 *
 * @v env		JNI environment
 */
static void jni_unregister_all ( JNIEnv *env ) {
	unsigned int i;

	/* Unregister all classes */
	for ( i = 0 ; i < ( sizeof ( jni_classes ) /
			    sizeof ( jni_classes[0] ) ) ; i++ ) {
		jni_unregister ( env, &jni_classes[i] );
	}
}

/**
 * Load JNI library
 *
 * @v vm		Java VM
 * @v reserved		Reserved
 * @ret version		Required JNI version
 */
JNIEXPORT jint JNI_OnLoad ( JavaVM *vm, void *reserved ) {
	JNIEnv *env;
	jint rc;

	( void ) reserved;

	/* Get JNI environment */
	if ( ( rc = (*vm)->GetEnv ( vm, ( void ** ) &env,
				    CX_JNI_VERSION ) ) != JNI_OK ) {
		DBG ( "JNI could not get environment: error %d\n", rc );
		return rc;
	}

	/* Register classes */
	if ( ! jni_register_all ( env ) )
		return JNI_ERR;

	return CX_JNI_VERSION;
}

/**
 * Unload JNI library
 *
 * @v vm		Java VM
 * @v reserved		Reserved
 */
JNIEXPORT void JNI_OnUnload ( JavaVM *vm, void *reserved ) {
	JNIEnv *env;
	jint rc;

	( void ) reserved;

	/* Get JNI environment */
	if ( ( rc = (*vm)->GetEnv ( vm, ( void ** ) &env,
				    CX_JNI_VERSION ) ) != JNI_OK ) {
		DBG ( "JNI could not get environment: error %d\n", rc );
		/* Give up; there is no corrective action available */
		return;
	}

	/* Unregister classes */
	jni_unregister_all ( env );
}
