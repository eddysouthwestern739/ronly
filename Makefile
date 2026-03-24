test-lima:
	limactl shell default bash -c \
	  'export CARGO_TARGET_DIR=/tmp/rosshd-target && \
	   cd /Users/ry/src/sshro && \
	   cargo build --release && \
	   sudo ROSSHD_BIN=/tmp/rosshd-target/release/rosshd \
	     bash tests/integration.sh'
