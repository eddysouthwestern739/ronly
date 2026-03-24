LIMA_CARGO = export CARGO_TARGET_DIR=/tmp/ronly-target && \
	cd /Users/ry/src/sshro

build-lima:
	limactl shell default bash -c \
	  '$(LIMA_CARGO) && \
	   $$HOME/.cargo/bin/cargo build --release 2>&1'

test-lima:
	limactl shell default bash -c \
	  '$(LIMA_CARGO) && \
	   sudo -E env "PATH=$$PATH" \
	     $$HOME/.cargo/bin/cargo test --release 2>&1'
