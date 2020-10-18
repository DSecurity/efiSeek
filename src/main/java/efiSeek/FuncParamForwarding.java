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
import java.util.HashSet;
import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

public class FuncParamForwarding {

	private FlatProgramAPI flatProgramAPI = null;
	private DecompInterface decomp = new DecompInterface();
	private HashSet<String> functions = new HashSet<String>();
	private int nameCount = 0;

	public FuncParamForwarding(Program prog) throws Exception {
		this.flatProgramAPI = new FlatProgramAPI(prog);
	}

	public void forward(Function startFunc, int paramNumber, String name, DataType type) throws Exception {
		this.decomp.openProgram(this.flatProgramAPI.getCurrentProgram());
		this.forwarding(startFunc, paramNumber, name, type);
		this.decomp.closeProgram();
	}

	public void forward(Function startFunc, int paramNumber) throws Exception {
		this.decomp.openProgram(this.flatProgramAPI.getCurrentProgram());
		this.forwarding(startFunc, paramNumber, null, null);
		this.decomp.closeProgram();
		this.functions.clear();
	}

	private Boolean checkEqualsNames(String name, Parameter[] paramArray) {
		for (Parameter param : paramArray) {
			if (param.getName().equalsIgnoreCase(name)) {
				return true;
			}
		}
		return false;
	}

	private void forwarding(Function startFunc, int paramNumber, String name, DataType type) throws Exception {
		DecompileResults res = this.decomp.decompileFunction(startFunc, 120, this.flatProgramAPI.getMonitor());
		if (res.decompileCompleted() == false) {
			Msg.error(this, "Error decompile func " + startFunc.getName());
			return;
		}

		HighFunction func = res.getHighFunction();
		FunctionPrototype funcProto = func.getFunctionPrototype();
		if (funcProto.getNumParams() < paramNumber + 1) {
			return;
		}
		HighSymbol needParam = funcProto.getParam(paramNumber);

		ArrayList<ParameterImpl> parametrs = new ArrayList<ParameterImpl>();
		Parameter[] parametrDefenitions = startFunc.getParameters();

		String tempName;
		if (checkEqualsNames(name, parametrDefenitions)) {
			tempName = name + this.nameCount++;
		} else
			tempName = name;

		if (name != null && type != null) {
			for (int i = 0; i < parametrDefenitions.length; i++) {

				if (i == paramNumber) {
					parametrs.add(new ParameterImpl(tempName, type, this.flatProgramAPI.getCurrentProgram()));
					continue;
				}
				parametrs.add(new ParameterImpl(parametrDefenitions[i].getName(), parametrDefenitions[i].getDataType(),
						this.flatProgramAPI.getCurrentProgram()));
			}

			ReturnParameterImpl returnValue = new ReturnParameterImpl(funcProto.getReturnType(),
					this.flatProgramAPI.getCurrentProgram());

			startFunc.updateFunction(null, returnValue, parametrs, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
					true, SourceType.ANALYSIS);
		} else {
			name = needParam.getName();
			type = needParam.getDataType();
		}
		Varnode needVar = needParam.getStorage().getFirstVarnode();
		Iterator<PcodeOpAST> pCodeIter = func.getPcodeOps();
		Iterator<PcodeOp> needPcodes = null;

		while (pCodeIter.hasNext()) {
			PcodeOpAST pCode = pCodeIter.next();
			if (pCode.getMnemonic().equalsIgnoreCase("CALL") || pCode.getMnemonic().equalsIgnoreCase("CAST")) {
				Varnode[] inputs = pCode.getInputs();
				for (Varnode in : inputs) {
					if (in.getSpace() == needVar.getSpace() && in.getOffset() == needVar.getOffset()) {
						needVar = in;
						needPcodes = in.getDescendants();
						break;
					}
				}
			}

			if (needPcodes != null)
				break;
		}

		if (needPcodes != null) {
			while (needPcodes.hasNext()) {
				PcodeOp pCode = needPcodes.next();
				Function callFunc = null;
				Varnode[] inputs;
				int varNumber;
				switch (pCode.getMnemonic()) {
				case "CALL":
					callFunc = this.getFunction(pCode.getInput(0));
					if (callFunc == null)
						break;
					if (!this.functions.add(callFunc.getName())) {
						return;
					}

					inputs = pCode.getInputs();
					varNumber = this.findVarnode(pCode.getInputs(), needVar);
					if (varNumber != -1)
						this.forwarding(callFunc, varNumber - 1, name, type);

					for (int i = 1; i < inputs.length; i++) {
						if (inputs[i] == needVar) {
							this.forwarding(callFunc, i - 1, name, type);
						}
					}
					break;
				case "CAST":
					Iterator<PcodeOp> castPcodeIter = pCode.getOutput().getDescendants();
					PcodeOp castPcode = castPcodeIter.next();
					if (castPcode.getMnemonic() == "CALL") {
						callFunc = this.getFunction(castPcode.getInput(0));
						if (callFunc == null)
							break;
						if (!this.functions.add(callFunc.getName())) {
							return;
						}

						varNumber = this.findVarnode(castPcode.getInputs(), pCode.getOutput());
						if (varNumber != -1)
							this.forwarding(callFunc, varNumber - 1, name, type);
					}

					break;
				default:
					break;
				}
			}
		}

		this.findGlobalEfiPointers(startFunc);
	}

	private Function getFunction(Varnode var) {
		if (var.isAddress()) {
			return this.flatProgramAPI.getFunctionAt(this.flatProgramAPI.toAddr(var.getOffset()));
		}
		return null;
	}

	private int findVarnode(Varnode[] varList, Varnode needVar) {
		for (int varNumber = 1; varNumber < varList.length; varNumber++) {
			if (varList[varNumber] == needVar) {
				return varNumber;
			}
		}
		return -1;
	}

	private void findGlobalEfiPointers(Function func) {
		DecompileResults res = this.decomp.decompileFunction(func, 120, this.flatProgramAPI.getMonitor());
		if (!res.decompileCompleted()) {
			Msg.error(this, "Error decompile func " + func.getName());
			return;
		}
		HighFunction updateFunc = res.getHighFunction();

		Iterator<PcodeOpAST> test = updateFunc.getPcodeOps();

		while (test.hasNext()) {
			Varnode var = test.next().getOutput();
			if (var != null && var.isAddress()) {
				String name = null;
				switch (var.getHigh().getDataType().getName()) {
				case "EFI_SYSTEM_TABLE *":
					name = "gST_" + this.nameCount++;
					break;
				case "EFI_BOOT_SERVICES *":
					name = "gBS_" + this.nameCount++;
					break;
				case "EFI_RUNTIME_SERVICES *":
					name = "gRS_" + this.nameCount++;
					break;
				case "EFI_HANDLE":
					name = "gImageHandle_" + this.nameCount++;
					break;
				default:
					break;
				}
				if (name != null) {
					Data existingData = this.flatProgramAPI.getDataAt(this.flatProgramAPI.toAddr(var.getOffset()));
					if (existingData != null) {
						try {
							this.flatProgramAPI.removeData(existingData);
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
					SymbolTable symbolTable = this.flatProgramAPI.getCurrentProgram().getSymbolTable();
					for (Symbol symbol : symbolTable.getSymbols(this.flatProgramAPI.toAddr(var.getOffset()))) {
						symbolTable.removeSymbolSpecial(symbol);
					}
					try {
						this.flatProgramAPI.createData(this.flatProgramAPI.toAddr(var.getOffset()),
								var.getHigh().getDataType());
						this.flatProgramAPI.createLabel(this.flatProgramAPI.toAddr(var.getOffset()), name, true, SourceType.ANALYSIS);
					} catch (Exception e) {
						Msg.warn(this, "Create data failed. Conflict at addr " + Long.toHexString(var.getOffset()));
						continue;
					}
				}
			}
		}
	}
}