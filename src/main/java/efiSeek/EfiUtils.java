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

import java.util.ArrayList;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.LabelHistory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public abstract class EfiUtils extends FlatProgramAPI {

	public final void defineData(Address address, DataType dataType, String name, String comment) throws Exception {
		for (int i = 0; i < dataType.getLength(); i++) {
			Address currentAddress = address.add(i);
			Data existingData = this.getDataAt(currentAddress);
			if (existingData != null) {
				this.removeData(existingData);
			} else {
				Instruction existingInstruction = this.getInstructionAt(currentAddress);
				if (existingInstruction != null) {
					this.removeInstruction(existingInstruction);
				}
			}
		}
		
		boolean primary = true;
		
		SymbolTable symbolTable = this.getCurrentProgram().getSymbolTable();
		for (Symbol symbol : symbolTable.getSymbols(address)) {
			if (symbol.getSource() != SourceType.USER_DEFINED) {
				symbolTable.removeSymbolSpecial(symbol);
			}
			else {
				primary = false;
			}
		}

		this.createData(address, dataType);

		if (name != null) {
			this.createLabel(address, name, primary, SourceType.ANALYSIS);
		}

		if (comment != null) {
			this.setPlateComment(address, comment);
		}
	}
	
	public final void defineVar(Variable var, DataType dataType, String name) throws Exception {
		if(var.getSource() != SourceType.USER_DEFINED) {
			var.setName(name, SourceType.ANALYSIS);
			var.setDataType(dataType, false, true, SourceType.ANALYSIS);
		}
	}

	public final String getLabel(Address addr) {
		SymbolTable symbolTable = getCurrentProgram().getSymbolTable();
		LabelHistory[] historyLable = symbolTable.getLabelHistory(addr);
		if (historyLable.length != 0) {
			return historyLable[historyLable.length - 1].getLabelString();
		}
		return null;
	}

	public final Address getEntryPoint() throws Exception {
		NTHeader ntHeader = null;
		byte[] blockBytes = new byte[(int) getCurrentProgram().getMemory().getSize()];
		int bytesRead = 0;
		for (MemoryBlock block : getCurrentProgram().getMemory().getBlocks()) {
			if (!block.isInitialized()) {
				continue;
			}
			bytesRead += block.getBytes(block.getStart(), blockBytes, bytesRead, (int) block.getSize());
		}
		FactoryBundledWithBinaryReader reader = new FactoryBundledWithBinaryReader(
				RethrowContinuesFactory.INSTANCE, new ByteArrayProvider(blockBytes),
				!getCurrentProgram().getLanguage().isBigEndian());
		int ntHeaderOffset = reader.readInt(0x3C);
		ntHeader = NTHeader.createNTHeader(reader, ntHeaderOffset,
		PortableExecutable.SectionLayout.FILE, false, false);

		long baseEntyPoint = ntHeader.getOptionalHeader().getAddressOfEntryPoint();
		return getCurrentProgram().getImageBase().add(baseEntyPoint);
	}

	public final Address readAddr(Address addr) throws MemoryAccessException {
		Address readAddr = null;
		readAddr = toAddr(((getByte(addr) & 0x00000000000000ffL) | (getByte(addr.add(1)) << 8 & 0x000000000000ff00L)
				| (getByte(addr.add(2)) << 16 & 0x0000000000ff0000L)
				| (getByte(addr.add(3)) << 24 & 0x00000000ff000000L)
				| (getByte(addr.add(4)) << 32 & 0x000000ff00000000L)
				| (getByte(addr.add(5)) << 40 & 0x0000ff0000000000L)
				| (getByte(addr.add(6)) << 48 & 0x00ff000000000000L)
				| (getByte(addr.add(7)) << 56 & 0xff00000000000000L)) & 0xfffffffffffffffL);
		return readAddr;
	}

	public final void createFunctionFormDifinition(Address funcAddr, FunctionDefinition defenition, String name)
			throws InvalidInputException, DuplicateNameException {

		ArrayList<ParameterImpl> parametrs = new ArrayList<ParameterImpl>();
		ParameterDefinition[] parametrDefenitions = defenition.getArguments();

		for (ParameterDefinition parameterDefinition : parametrDefenitions) {
			parametrs.add(new ParameterImpl(parameterDefinition.getName(), parameterDefinition.getDataType(),
					getCurrentProgram()));
		}

		if (name == null) {
			name = defenition.getName();
		}

		Function func = getFunctionAt(funcAddr);
		if (func == null) {
			func = this.createFunction(funcAddr, name);
			if (func == null) {
				Msg.error(this, "Can't create function!");
				Msg.error(this, funcAddr.toString());
				return;
			}
		} else {
			func.setName(name, SourceType.ANALYSIS);
		}

		ReturnParameterImpl returnValue = new ReturnParameterImpl(defenition.getReturnType(), getCurrentProgram());

		func.updateFunction(null, returnValue, parametrs, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false,
				SourceType.ANALYSIS);
	}
}