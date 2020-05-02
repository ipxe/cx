/* JNI library wrapper */

#include <cx/jni.h>

#define REQUIRE( symbol ) const void * import_ ## symbol = symbol

REQUIRE ( JNI_OnLoad );
REQUIRE ( JNI_OnUnload );
