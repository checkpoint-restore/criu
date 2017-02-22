all-y	+= libpy-images rpc_pb2.py

.PHONY: .FORCE

$(obj)/images/%: .FORCE
	$(Q) $(MAKE) $(build)=$(obj)/images $@

libpy-images:
	$(Q) $(MAKE) $(build)=$(obj)/images all
.PHONY: libpy-images

rpc_pb2.py:
	$(Q) protoc -I=$(SRC_DIR)/images/ --python_out=$(obj) $(SRC_DIR)/images/$(@:_pb2.py=.proto)

cleanup-y	+= $(addprefix $(obj)/,rpc_pb2.py *.pyc)

clean-lib-py:
	$(Q) $(MAKE) $(build)=$(obj)/images clean
.PHONY: clean-lib-py
clean: clean-lib-py
