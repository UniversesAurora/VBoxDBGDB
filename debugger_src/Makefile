#
# Copyright (C) 2009-2020 Oracle Corporation
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#

PATH_SDK      = ../../..
CAPI_INC      = -I$(PATH_SDK)/bindings/c/include
ifeq ($(BUILD_PLATFORM),win)
PLATFORM_INC  = -I$(PATH_SDK)/bindings/mscom/include
PLATFORM_LIB  = $(PATH_SDK)/bindings/mscom/lib
else
PLATFORM_INC  = -I$(PATH_SDK)/bindings/xpcom/include
PLATFORM_LIB  = $(PATH_SDK)/bindings/xpcom/lib
endif
GLUE_DIR      = $(PATH_SDK)/bindings/c/glue
GLUE_INC      = -I$(GLUE_DIR)

CC            = gcc
CFLAGS        = -g -Wall -std=gnu99

.PHONY: all
all: server

.PHONY: clean
clean:
	rm -f server.o dbgapi.o dbgbreakpoint.o dbgshell.o dbgshellcmd.o dbggdbserver.o gdbserver.o utils.o packets.o signals.o VBoxCAPIGlue.o VirtualBox_i.o server *.log

server: server.o dbgapi.o dbgbreakpoint.o dbgshell.o dbgshellcmd.o dbggdbserver.o gdbserver.o utils.o packets.o signals.o VBoxCAPIGlue.o VirtualBox_i.o
	$(CC) -o $@ $^ -ldl -lpthread

server.o: server.c
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<

dbgapi.o: dbgapi.c
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<

dbgbreakpoint.o: dbgbreakpoint.c
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<

dbgshell.o: dbgshell.c
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<

dbgshellcmd.o: dbgshellcmd.c
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<

dbggdbserver.o: dbggdbserver.c
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<

gdbserver.o : gdbserver.c arch.h utils.h packets.h gdb_signals.h
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<

signals.o : signals.c gdb_signals.h gdb/signals.h gdb/signals.def
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<

VBoxCAPIGlue.o: $(GLUE_DIR)/VBoxCAPIGlue.c
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<

VirtualBox_i.o: $(PLATFORM_LIB)/VirtualBox_i.c
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<

%.o: %.c
	$(CC) $(CFLAGS) $(CAPI_INC) $(PLATFORM_INC) $(GLUE_INC) -o $@ -c $<
