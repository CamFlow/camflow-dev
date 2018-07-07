# SYNOPSIS
#
#   AX_GCC_PLUGIN
#
# DESCRIPTION
#
#   This macro locates the headers necessary to compile a GCC plug-in.
#
#   If the --with-gcc-includes option is set to a directory, the macro
#   checks for the tree.def header in that directory.  Otherwise, it
#   looks for the include directory belonging to the actual build
#   compiler (speified with CC).
#
#   AX_GCC_PLUGIN() fails with an error if it cannot find tree.def.
#
#   This macro calls:
#
#     AC_SUBST(gcc_includes)
#
# LICENSE
#
#    Copyright (c) 2009 Stony Brook University
#
#   Copying and distribution of this file, with or without
#   modification, are permitted in any medium without royalty provided
#   the copyright notice and this notice are preserved.

AC_DEFUN([AX_GCC_PLUGIN],
[
  AC_ARG_WITH(
    [gcc_includes],
    AC_HELP_STRING([--with-gcc-includes], [Full path to directory with gcc plug-in header files. By default configure will ask GCC for this directory.]),
    [gcc_includes=$withval],
    [gcc_includes=`"$CC" -print-file-name=plugin`/include])

  # Don't let the user specify --with-gcc-includes=no or --without-gcc-includes.
  # That's bogus.
  AS_IF(
    [test "x$gcc_includes" == xno],
    AC_MSG_FAILURE([Plug-ins cannot compile without a plug-in includes directory.]))

  # If you ask a pre-plug-in GCC for the plug-in includes directory,
  # it just returns "plugin"
  AS_IF(
    [test "x$gcc_includes" == xplugin/include],
    AC_MSG_FAILURE([Bad plugin directory.  It looks like you are not using a plug-in-capable GCC.]))

  # Make sure the path looks like an absolute path.
  case "$gcc_includes" in
      /*) ;;
      ~*) ;;
      *)
          gcc_includes==`pwd`/$gcc_includes
          ;;
  esac

  # Final check.  Did we actually find a directory with plug-in header files?
  AS_IF(
    [test "x$gcc_includes" == x -o ! -f "$gcc_includes/tree.def"],
    AC_MSG_FAILURE([Cannot find plug-in headers in $gcc_includes]))

  AC_MSG_NOTICE([Using GCC headers at $gcc_includes])
  AC_SUBST([gcc_includes], [$gcc_includes])
])
