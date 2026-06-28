CXXFLAGS   = -Wall -O3 -std=c++20
INCLUDEDIR = -I./ -I/usr/include/ -I/usr/local/include/
LDFLAGS    = -L/usr/lib -L/usr/local/lib

OUTPUT     = bin/fibmgr
SOURCES    = main.cpp fibmgr.cpp
OBJECTS    = ${SOURCES:S/.cpp$/.o/:S/^/obj\//}

.PHONY: all clean install uninstall

all: ${OUTPUT}

${OUTPUT}: ${OBJECTS}
	@mkdir -p ${.TARGET:H}
	@c++ ${LDFLAGS} ${LDLIBS} ${OBJECTS} -o ${.TARGET}

${OBJECTS}: ${SOURCES}
	@mkdir -p ${.TARGET:H}
	@c++ ${INCLUDEDIR} ${CXXFLAGS} -c ${.ALLSRC:M*${.TARGET:T:R}.cpp} -o ${.TARGET}

install:
	@cp ${OUTPUT} /usr/local/bin

uninstall:
	@rm -f /usr/local/bin/${OUTPUT:T}

clean:
	@rm -rf ${.CURDIR}/bin ${.CURDIR}/obj
	@rm -f *.o *~
