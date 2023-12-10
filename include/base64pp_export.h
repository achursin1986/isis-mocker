/* MIT License

Copyright (c) 2022 - Matheus Gomes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */




#ifndef BASE64PP_EXPORT_H
#define BASE64PP_EXPORT_H

#ifdef BASE64PP_STATIC_DEFINE
#  define BASE64PP_EXPORT
#  define BASE64PP_NO_EXPORT
#else
#  ifndef BASE64PP_EXPORT
#    ifdef base64pp_EXPORTS
        /* We are building this library */
#      define BASE64PP_EXPORT 
#    else
        /* We are using this library */
#      define BASE64PP_EXPORT 
#    endif
#  endif

#  ifndef BASE64PP_NO_EXPORT
#    define BASE64PP_NO_EXPORT 
#  endif
#endif

#ifndef BASE64PP_DEPRECATED
#  define BASE64PP_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef BASE64PP_DEPRECATED_EXPORT
#  define BASE64PP_DEPRECATED_EXPORT BASE64PP_EXPORT BASE64PP_DEPRECATED
#endif

#ifndef BASE64PP_DEPRECATED_NO_EXPORT
#  define BASE64PP_DEPRECATED_NO_EXPORT BASE64PP_NO_EXPORT BASE64PP_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef BASE64PP_NO_DEPRECATED
#    define BASE64PP_NO_DEPRECATED
#  endif
#endif

#endif /* BASE64PP_EXPORT_H */
