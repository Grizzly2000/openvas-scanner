#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void concat_str(char **dst, const char *str) {
    char *tmp = NULL;

    // Reset *dst
    if ( *dst != NULL && str == NULL ) {
        free(*dst);
        *dst = NULL;
        return;
    }

    // Initial copy
    if (*dst == NULL) {
        *dst = calloc( strlen(str)+1, sizeof(char) );
        memcpy( *dst, str, strlen(str) + 1);
    }
    else { // Append
        tmp = calloc( strlen(*dst)+1, sizeof(char) );
        memcpy( tmp, *dst, strlen(*dst) );
        free(*dst);
        *dst = calloc( strlen(tmp)+strlen(str)+1, sizeof(char) );
        memcpy( *dst, tmp, strlen(tmp) );
        memcpy( *dst + strlen(tmp), str, strlen(str) + 1);
        free(tmp);
    }

}