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



import ghidra.app.util.bin.ByteProvider;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.util.bin.format.pe.MachineConstants;

public class EfiSeekAnalyzer extends AbstractAnalyzer {

	private String gdtFileName = null;
	private NTHeader ntHeader = null;

	public EfiSeekAnalyzer() {

		super("efiSeek", "Analyze UEFI firmware, find major struct and functions.",
				AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!program.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			return false;
		}

		try {
			byte[] blockBytes = new byte[(int) program.getMemory().getSize()];
			int bytesRead = 0;
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!block.isInitialized()) {
					continue;
				}
				bytesRead += block.getBytes(block.getStart(), blockBytes, bytesRead, (int) block.getSize());
			}
			BinaryReader reader = new BinaryReader(
				new ByteArrayProvider(blockBytes),
				!program.getLanguage().isBigEndian());
			int ntHeaderOffset = reader.readInt(0x3C);
			ntHeader = new NTHeader(reader, ntHeaderOffset,
							PortableExecutable.SectionLayout.FILE, false, false);
		} catch (Exception e) {
			return false;
		}

		OptionalHeader optionalHeader = ntHeader.getOptionalHeader();

		int subsystem = optionalHeader.getSubsystem();
		if (subsystem >= 10 && subsystem <= 13) {
			return true;
		}
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		short machine = ntHeader.getFileHeader().getMachine();
		monitor.setIndeterminate(true);
		switch (machine) {
		case MachineConstants.IMAGE_FILE_MACHINE_AMD64:
			this.gdtFileName = "Behemotx64.gdt";
			break;
		case MachineConstants.IMAGE_FILE_MACHINE_I386:
			this.gdtFileName = "Behemotx32.gdt";
			break;
		default:
			Msg.error(this, "Unknown arch");
			return false;
		}
		FlatProgramAPI flatProgramAPI = new FlatProgramAPI(program);
		if (program.isLocked() == false) {
			try {
				program.setImageBase(flatProgramAPI.toAddr(0x80000000), true);
			} catch (AddressOverflowException | LockException | IllegalStateException e) {
				Msg.error(this, "Problems with installing the base address");
				e.printStackTrace();
			}
		}

		EfiSeek EfiTool = new EfiSeek(program, gdtFileName);
		EfiTool.updateMemBlockPermission();
		EfiTool.findGuids();
		try {
			EfiTool.forwardSystemTable();
		} catch (Exception e) {
			Msg.error(this, "Problems with forwarding System Table");
			e.printStackTrace();
		}
		try {
			EfiTool.defineUefiFunctions();
		} catch (Exception e) {
			Msg.error(this, "Problems with defining EFI Functions");
			e.printStackTrace();
		}
		return true;
	}
}
