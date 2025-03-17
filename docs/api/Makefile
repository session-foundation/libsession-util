H_FILES = $(wildcard ../../include/session/config/*.h ../../include/session/config/*/*.h)
HPP_FILES = $(wildcard ../../include/session/config/*.hpp ../../include/session/config/*/*.hpp)

.PHONY: clean
clean:
	rm -rf ./dist

.PHONY: build-hpp
build-hpp:
	./make-docs.sh dist/libsession-util-cpp $(HPP_FILES)

.PHONY: build-h
build-h:
	./make-docs.sh dist/libsession-util-c $(H_FILES)

.PHONY: build-all
build-all: build-h build-hpp

.PHONY: serve-c
serve-c:
	cd dist/libsession-util-c/site && python -m http.server 8000 && cd -

.PHONY: serve-cpp
serve-cpp:
	cd dist/libsession-util-cpp/site && python -m http.server 8001 && cd -

# Developer commands: Build and serve a site inside of dist/ using the mkdocs development server.
# NOTE: Any changes to dist/ will be hot-reloaded but are not tracked by git.

.PHONY: dev-c
dev-c: build-h
	cd dist/libsession-util-c && mkdocs serve && cd -

.PHONY: dev-cpp
dev-cpp: build-hpp
	cd dist/libsession-util-cpp && mkdocs serve && cd -
