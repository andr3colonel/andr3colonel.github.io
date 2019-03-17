---
layout: post
title:  "Writing a wasm loader for Ghidra. Part 2: Implement loader"
date: 2019-03-17
categories: ghidra
tags: ghidra, WebAssembly
excerpt: 
mathjax: true
---

<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/ghidra.png"/></div>


In the previous  [article](https://andr3colonel.github.io/2019/03/12/ghidra-wasm-loader/)
 I’ve described how to build the simple module to parse WebAssembly binary loader for the Ghidra. The module, I've created, contained blank loader, blank analyzer, and placeholder for the processor. The only functionality it provided -- verification of the header and suggesting the loader which will parse input file. 

In this article I’m going to finish implementation of the loader. I'll tell how to parse binary file and show its structure in human-readable representation, using WebAssembly format as example.

But before I dive into coding, I propose to review the workflow of file analysis and understand what callbacks Ghidra provides to the developer. I've learned it, studying sources of ghidra and propose to do this to everyone who want to develp own module. Sources are clean to understanding and easy to read.   










<img align="right" src="https://andr3colonel.github.io/images/post2/pic2.png"/>

After the user creates project, and choses what file he wants to import, Ghidra passes the file to method getSupportedLoadSpecs of the class LoaderService. The method tries to find all possible loaders, that can process choosen file. It gathers all the objects, instantiated from the AbstractProgramLoader or it’s sublasses (loaders) and calls the method findSupportedLoadSpecs from each of them. (I've already implemented this method in previous article),

The method checks is loader able to process given file, and returns back array of the LoadSpec objects. Each object contains information of those who will further process the file and what Processor will be used to disassembly instructions. 

Ghidra takes the output of query to LoaderService and use it to fill the fields of import dialog, allowing user to choose which loader Ghidra will use to process the file.

After the user chooses parameters and clicks OK button, Ghidra calls method load of chosen loader. The method creates and returns back object of the class Program, which represents the memory, the symbols and the listing of processed file. 
There are number of template classes, inherited from the AbstractProgram, taking initial setup and initialisation of the Program. I’ve decided to use AbstractLibrarySupportLoader as base class for my loader, because, according documentation, it “provides a framework to conveniently load Programs with support for linking against libraries contained in other Programs”. As far as binary contains import section, it would be convenient to use this class to show import methods from there. Additional advantage that the class is already implemented initialization of program and the only duty of the developer is to parse format and place it to the memory of program. After program initialisation's done, the class calls abstract method load, which should be overridden by developer in the subclass. This method allocates addition program memory, processes relocations and adds symbols. API process the following methods, that will come in handy:

<ul>
<li>
MemoryBlockUtil.createInitializedBlock. The method creates block in the virtual memory of the program and fills it with the values from the source. Ghidra will shows created blocks in the UI window “Program Trees"

<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/pic4.png"/></div>
</li>
    <li>
DataUtilities.createData. It takes the structure, introduced by the object of DataType class, and applies it to the given address. Ghidra will annotate the data at the address according to the format of the structure:

<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/pic5.png"/></div>
</li>

<li>
FunctionManager.CreateFunction. It marks range of memory as function. In the listing ghidra adds headers before the addresses marked as function.

<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/pic6.png"/></div>
</li>


Symbols, marked as methods, are exposed to the Function directory of the Symbols tree.

<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/pic6.png"/></div>

</ul>


Now, let’s see how is wasm format works and what information I can get from there to achieve the goal. Unfortunately I’m not have too much time to implement everything, so I will focus on structures, helping to solve the challenge. But uou can read the comprehensive description of the wasm format at this outstanding repository of Dan Gohman.

In high-level terms, structure of the wasm file can be represented by the following table: 


<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/pictable.png"/></div>


File starts with a header, containing magic identifier “\0asm” and version of the file format. The header is followed by a sequence of sections. Each section contains identifier, length of the data (in bytes) and, actually data. Format of the data depends on the ty. of the section. 
There are two categories of the sections. Custom section is aimed to extension of the format by developer, has 0 in the id field, and is out of scope of this article. Known section has Id in range 1-11, and defined in the  specification of the format. 
The most interesting sections from reverse-engineering perspective are those which contain metadata and instructions for the methods. I’ve represented them as entity-relation diagram:

<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/pic3.png"/></div>

Section “functions” binds metadata from section Type and Export to instructions from section Code. Exports and type contain information about method: name and parameters, while the entries from code section contain code instructions. 
All the numbers in WebAssembly are represented by LEB128 format -- variable-length format to endode integer values.

Now it’s time to implement obtained knowledge into the code. As usual, you can get the full code from the repository. In the article I’ll tell stop on the code, essential to understanding development process of the loader.

All the classes, describing the structures of wasm in my module consist of two parts. First part is placed in constructor and deserialize data from BinaryReader to java objects. Second part converts analyse read data and returns description of its structure. To build it, I make every structure class to implement interface StuctureConverter. It introduces contract, obligating it’s subclases to return DataType object. This object later will be used to map structures to address space and make it human-readable. 

Easiest example of this class is the header structure: it has fixed eight bytes size and only two fields: string magic and double word version. 


```java
    private byte[] magic;
    private int version;
```

```java
//First part: constructor which deserializes data from 
//input stream to java fields
public WasmHeader(BinaryReader reader) throws IOException {
        //read magic string
        magic = reader.readNextByteArray( WasmConstants.WASM_MAGIC_BASE.length() );
        //read integer version
        version = reader.readNextInt();
        if (!WasmConstants.WASM_MAGIC_BASE.equals(new String(magic))) {
            throw new IOException("not a wasm file.");
        }
  }
```

Method annotating this structure is pretty straight-forward. It creates object of the class Structure and fill it with the information about fields. To add the field to structure it uses the method add, taking as arguments field’s type, size and name. 

```java
@Override
public DataType toDataType() throws DuplicateNameException, IOException {
//create named structure
    Structure structure = new StructureDataType("header_item", 0);
//the first item of the structure is a string, it’s size is four bytes
    structure.add(STRING, 4, "magic", null);
   //the second of the structure is a string, it’s size is four bytes
    structure.add(DWORD, 4, "version", null);
    return structure;
}
```

Later on, structure will be passed to method createData, telling Ghidra, that data on start of program has a header format. 

```java
Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
createData(program, program.getListing(), start, header.toDataType());
```

Result of execution of the code is on picture:


<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/pic8.png"/></div>
<br>

It works well for the fixed-size structures, but very often size of structure is variable and depends on data. As I told before, all the numbers in wasm format are encoded into the Leb128 format. Parsing this format, application reads bytes one-by-one, until it met byte which highest bit is non-zero. In other words, result size may be from one to five bytes. Processing the file, class Leb128 represents itself as one the primitive integer types, basing on data size.

```java
@Override
public DataType toDataType() throws DuplicateNameException, IOException {
    length = Leb128.unsignedLeb128Size(value);
    switch (length) {
        case 1:
            return ghidra.app.util.bin.StructConverter.BYTE;
        case 2:
            return ghidra.app.util.bin.StructConverter.WORD;     
        case 4:
            return ghidra.app.util.bin.StructConverter.DWORD;
    }
    return null;        
}
```

Let’s see how it works on real word. For example we have structure with two fields: body_size and local_count, encoded to Leb128 format

```java
private Leb128 body_size; // 0x99 0x02
private Leb128 local_count; // 0x01
```

During initialization they read their values from BinaryReader object. Let’s assume that body_size has two-bytes lengths and local_count is just one byte. 

```java
private Leb128 body_size = new Leb128(reader); // 0x99 0x02
private Leb128 local_count  = new Leb128(reader); // 0x01
```

As before, method toDataType creates structure, but instead of usage of predefined types and hardcoded length, it uses type returned by Leb128 object

```java
@Override
public DataType toDataType() throws DuplicateNameException, IOException {
//create named structure
    Structure structure = new StructureDataType("function_1", 0);
//this time type and the length of the field is depends on data. 
//in this case type of the body_size is WORD and size is two bytes
    structure.add(body_size.toDataType(), body_size.toDataType().getLength(), "body_type", null);
   //type of the local_count is BYTE and size is one byte
    structure.add(local_count.toDataType(), local_count.toDataType().getLength(), "local_count", null);
    return structure;
}
```

When this data type will be mapped on data, it will looks like that, correctly representing the variable LEB128 format. 

<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/pic8_.png"/></div>

Code, parsing the whole section is bit more complex, but is based on the same principle: it’s need to create structure and add fields, considering that field can have composed type. 
I’ll demonstrate it on example of exports section. As every section, it starts with the header, containing id and size. After the header it has a field, telling number of entries and the sequence of export entries.

```java
private byte id;
private Leb128 size; 
private Leb128 entries_count; 
private List<WasmExportEntry> exports = new ArrayList<WasmExportEntry>();
```

Export entry implements interface StructureConverter, and returns own structure from method toDataType as well. Method toDataType of the class ExportSection takes the returned structure and adds it to own result, creating hierarchical type. 

```java
@Override
public DataType toDataType() throws DuplicateNameException, IOException {
        Structure structure = new StructureDataType("ExportSection", 0);
    //adds field of primitive type, returned by Leb128 structure
        structure.add(count.toDataType(), count.toDataType().getLength(), "count", null);
    //adds to result complex structure returned by WasmExportEntry
        for (int i = 0; i < count.getValue(); ++i) {
            structure.add(exports[i].toDataType(), exports.[i].toDataType().getLength(), "export_"+i, null);
       }        
    return structure;
}
```

After mapping the structure on data, ghidra shows hierarchy of nested structures. There’s a main structure .code, containing payload structure CodeSection, which in his turn includes structure function. Data became structured and easy to read.


<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/pic9.png"/></div>



The only problem is that instructions, marked as part of structure can’t be decompiled. It's bit annoying because I'd like to have both, file structure and code representation of file being analysed. But in this case it’s possible to find workaround. The WebAssembly instructions are high-level, and don’t operate addresses, calling methods by their indexes. Therefore, I can create one more “virtual” space for the code, and copy there the instructions of all methods contained in application:

```java
//Create memory block for the instructions
Address address = Utils.toAddr( program, Utils.METHODS_BASE_ADDRESS );
MemoryBlock block = program.getMemory( ).createInitializedBlock( "method_bytecode", address, length, (byte) 0xff, monitor, false );

//for each method copy instructions to virtual memory
for (WasmFunctionBody method: codeSection.getFunctions()) {
    long method_offset = code_offset + method.getOffset(); 
    Address methodAddress = Utils.toAddr( program, Utils.METHODS_BASE_ADDRESS + method_offset );
    byte [] instructionBytes = method.getInstructions();
    program.getMemory( ).setBytes( methodAddress, instructionBytes );
}
```

It's only left to mark each method as function, calling the method createFunction, mentioned above. 

```java
program.getFunctionManager().createFunction("Method_" + lookupOffset, methodAddress, new AddressSet(methodAddress, methodend), SourceType.ANALYSIS);
```

So, at the and of the day I've built loader, able to parse and annotate Webassembly format. In the next article I’ll try to implement WebAssembly processor, able to disassembly the code

<div style="text-align:center"><img align="middle" src="https://andr3colonel.github.io/images/post2/code_format.png"/></div>

Thanks to those who succeed to read the article till the end. Don't hesitate to ask me in social networks, using contacts in footer, if you have any questions about the module. 