/*
 * data.c
 * libclosure
 *
 * Copyright (c) 2008-2010 Apple Inc. All rights reserved.
 *
 * @APPLE_LLVM_LICENSE_HEADER@
 *
 */

/********************
 *  NSBlock support
 *
 *  We allocate space and export a symbol to be used as the Class for the on-stack and malloc'ed copies until ObjC arrives on the scene.  These data areas are set up by Foundation to link in as real classes post facto.
 *
 *  We keep these in a separate file so that we can include the runtime code in test subprojects but not include the data so that compiled code that sees the data in libSystem doesn't get confused by a second copy.  Somehow these don't get unified in a common block.
 **********************/

void * _NSConcreteStackBlock[32] = { 0 };
void * _NSConcreteMallocBlock[32] = { 0 };
void * _NSConcreteAutoBlock[32] = { 0 };
void * _NSConcreteFinalizingBlock[32] = { 0 };
void * _NSConcreteGlobalBlock[32] = { 0 };
void * _NSConcreteWeakBlockVariable[32] = { 0 };
