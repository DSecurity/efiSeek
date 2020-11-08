//
//@TheJokiv 
//@UEFI

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import org.json.JSONObject;

public class TransferEfiFilesToProject extends HeadlessScript {

	@Override
	protected void run() throws Exception {
		String folderName = null;
		this.setHeadlessImportDirectory(null);
		String[] args = getScriptArgs();
		if (args.length < 1)
			return;
		if (this.isRunningHeadless()) {
			MemoryBlock metaBlock = this.getMemoryBlock("metaBlock");
			if(metaBlock != null) {
				byte[] raw = new byte[(int) metaBlock.getSize()];
				try {
					metaBlock.getBytes(metaBlock.getStart(), raw);
				} catch (MemoryAccessException e) {
					Msg.info(this, "Can't read metaBlock");
					e.printStackTrace();
					return;
				}
				String metaStr = new String(raw);
				JSONObject meta = new JSONObject(metaStr);
				JSONObject interrupts = meta.getJSONObject("interrupts");
				JSONObject childSmi = interrupts.getJSONObject("child");
				JSONObject swSmi = interrupts.getJSONObject("swSmi");
				JSONObject hwSmi = interrupts.getJSONObject("hwSmi");


				if (!hwSmi.isEmpty()) {
					folderName = "HwSmi";
					print("HwSmi found");
				}
				else {
					print("HwSmi is missing from the module!");
				}
				if (!childSmi.isEmpty()) {
					folderName = "ChildInter";
					print("ChildSmi found");
				} else {
					print("ChildInter is missing from the module!");
				}
				if (!swSmi.isEmpty()) {
					folderName = "SwSmi";
					print("SwSmi found");
				} else {
					print("SwSmi is missing from the module!");
				}

				if (folderName != null) {
					this.setHeadlessImportDirectory(args[0] + "/" + folderName);
				}
			}
		}
	}
}
