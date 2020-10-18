//	 Copyright (c) 2020 Digital Security. All rights reserved.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package efiSeek;

import java.nio.ByteBuffer;

public class Guid {
	private int data1;
	private short data2;
	private short data3;
	private byte[] data4 = new byte[8];

	public Guid(byte[] raw_guid) {
		this.data1 = 0xffffffff & (raw_guid[0] & 0xff | ((raw_guid[1] << 8) & 0xff00) | ((raw_guid[2] << 16) & 0xff0000)
				| ((raw_guid[3] << 24) & 0xff000000));
		this.data2 = (short) (0xffff & (raw_guid[4] & 0xff | (raw_guid[5] << 8) & 0xff00));
		this.data3 = (short) (0xffff & (raw_guid[6] & 0xff | (raw_guid[7] << 8) & 0xff00));
		for (int i = 0; i < 8; i++) {
			this.data4[i] = raw_guid[i + 8];
		}
	}

	public Guid(String guid) {
		String delims = "[-]";
		String[] guidPart = guid.split(delims);
		byte[] rawGuid = new byte[16];

		for (int i = 0, offset = 0; i < guidPart.length; i++) {
			System.arraycopy(this.asBytes(guidPart[i]), 0, rawGuid, offset, this.asBytes(guidPart[i]).length);
			offset += this.asBytes(guidPart[i]).length;
		}

		this.data1 = 0xffffffff & (rawGuid[3] & 0xff | ((rawGuid[2] << 8) & 0xff00) | ((rawGuid[1] << 16) & 0xff0000)
				| ((rawGuid[0] << 24) & 0xff000000));
		this.data2 = (short) (0xffff & (rawGuid[5] & 0xff | (rawGuid[4] << 8) & 0xff00));
		this.data3 = (short) (0xffff & (rawGuid[7] & 0xff | (rawGuid[6] << 8) & 0xff00));
		for (int i = 0; i < 8; i++) {
			this.data4[i] = rawGuid[i + 8];
		}
	}

	private byte[] asBytes(String s) {
		String tmp;
		byte[] b = new byte[s.length() / 2];
		int i;
		for (i = 0; i < s.length() / 2; i++) {
			tmp = s.substring(i * 2, i * 2 + 2);
			b[i] = (byte) (Integer.parseInt(tmp, 16) & 0xff);
		}
		return b;
	}

	public String toString() {
		String guid = "";
		byte[] rawGuid = new byte[16];
		System.arraycopy(ByteBuffer.allocate(4).putInt(this.data1).array(), 0, rawGuid, 0, 4);
		System.arraycopy(ByteBuffer.allocate(2).putShort(this.data2).array(), 0, rawGuid, 4, 2);
		System.arraycopy(ByteBuffer.allocate(2).putShort(this.data3).array(), 0, rawGuid, 6, 2);
		System.arraycopy(this.data4, 0, rawGuid, 8, 8);

		for (int i = 0; i < 16; i++) {
			if (i == 4)
				guid += "-";
			if (i == 6)
				guid += "-";
			if (i == 8)
				guid += "-";
			if (i == 10)
				guid += "-";
			if ((rawGuid[i] >> 4 & 0xf) == 0) {
				guid += "0";
			} else if ((rawGuid[i] & 0xff) == 0) {
				guid += "00";
			}
			guid += Integer.toHexString(rawGuid[i] & 0xff);
		}
		return guid;
	}

	public byte[] toRaw() {
		byte[] rawGuid = new byte[16];

		System.arraycopy(ByteBuffer.allocate(4).putInt(Integer.reverseBytes(this.data1)).array(), 0, rawGuid, 0, 4);
		System.arraycopy(ByteBuffer.allocate(2).putShort(Short.reverseBytes(this.data2)).array(), 0, rawGuid, 4, 2);
		System.arraycopy(ByteBuffer.allocate(2).putShort(Short.reverseBytes(this.data3)).array(), 0, rawGuid, 6, 2);
		System.arraycopy(this.data4, 0, rawGuid, 8, 8);

		return rawGuid;
	}
}