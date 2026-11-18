#ifndef VBC_I18N_RESOURCE_ORIGIN_H
#define VBC_I18N_RESOURCE_ORIGIN_H
#include <stddef.h>
#include <stdint.h>
#include "i18n_loaded_origin.h"
extern "C" {
/* Origin only, never locale/readiness authorization. Owning UI frame required; returns a copy, no borrowed pointers. */
void vbc_i18n_modern_forget(uintptr_t file);
void vbc_i18n_modern_open(uintptr_t manager,uintptr_t file,const char *path,size_t size,const char *project,size_t project_size);
void vbc_i18n_modern_bind(uintptr_t file,uintptr_t dictionary,const char *uri,size_t size);
void vbc_i18n_modern_remove(uintptr_t manager,const char *project,size_t size);
int vbc_i18n_resource_origin_at(uintptr_t manager,unsigned index,VbcLoadedOrigin *out);
int vbc_i18n_resource_origin(uintptr_t manager, uintptr_t directory, VbcLoadedOrigin *out);
void *vbc_i18n_directory_from_file(void *manager, const char *data, size_t size);
void vbc_i18n_resource_set_kzb(void *resource, const void *directory, const char *data, size_t size);
void vbc_i18n_remove_directory(void *manager, void *directory);
}
#endif
