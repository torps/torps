
.PHONY: cpp python

all:
	@echo "Use either 'cpp' or 'python' target"

cpp: protobuf-2.5.0/src/protoc 
	protobuf-2.5.0/src/protoc message_spec.proto --cpp_out=$(TARGET_DIR)

python: protobuf-2.5.0/src/protoc  
	protobuf-2.5.0/src/protoc message_spec.proto --python_out=$(TARGET_DIR)

protobuf-2.5.0/src/protoc:
	cd protobuf-2.5.0 && ./configure --disable-shared
	$(MAKE) -C protobuf-2.5.0
