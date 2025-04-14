#!/bin/bash
git config --global --add safe.directory /go/src

echo "Build ${ARTIFACT_NAME} in ${BIN_OS}_${BIN_ARCHS}"; 
if [[ "$BIN_OS" == "windows" ]]; then
		for ARCH in ${BIN_ARCHS}; do\
			echo "Build windows in ARCH: ${ARCH}"; \
            cd /go/src && IS_DOCKER=true GOOS=${BIN_OS} GOARCH=${ARCH} make bin; \	
			cp bin/bao builds/bao.exe; \
			chmod 777 -R /go/src/bin; \
            cd builds; \
			zip -9 ${ARTIFACT_NAME}_windows_${ARCH}.zip bao.exe; \
			shasum -a 256 ${ARTIFACT_NAME}_windows_${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
			cd ..; \
			rm builds/bao.exe; \
		done;
else
		for ARCH in ${BIN_ARCHS}; do\
			echo "Build ${BIN_OS} in ARCH: ${ARCH}"; \
            cd /go/src && IS_DOCKER=true GOOS=${BIN_OS} GOARCH=${ARCH} make bin; \	
			cp bin/bao builds/bao; \
            chmod 777 -R /go/src/bin; \
			cd builds; \
			zip -9 ${ARTIFACT_NAME}_${BIN_OS}_${ARCH}.zip bao; \
			shasum -a 256 ${ARTIFACT_NAME}_${BIN_OS}_${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
			cd ..; \
			rm builds/bao; \
		done;

fi

echo "END Build ${ARTIFACT_NAME} in ${BIN_OS}_${BIN_ARCHS}"; 




