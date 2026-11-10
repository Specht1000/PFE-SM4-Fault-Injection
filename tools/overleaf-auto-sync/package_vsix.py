"""Build the dependency-free local extension package without a package registry."""
from pathlib import Path
import json
import zipfile
from xml.sax.saxutils import escape

root = Path(__file__).resolve().parent
package = json.loads((root / "package.json").read_text(encoding="utf-8"))
manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Language="en-US" Id="{escape(package['name'])}" Version="{escape(package['version'])}" Publisher="{escape(package['publisher'])}"/>
    <DisplayName>{escape(package['displayName'])}</DisplayName>
    <Description xml:space="preserve">{escape(package['description'])}</Description>
    <Categories>Other</Categories>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="{escape(package['engines']['vscode'])}"/>
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="iamhyc.overleaf-workshop"/>
      <Property Id="Microsoft.VisualStudio.Code.ExecutesCode" Value="true"/>
    </Properties>
  </Metadata> 
  <Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation>
  <Dependencies/>
  <Assets><Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/></Assets>
</PackageManifest>'''
types = '''<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
  <Default Extension="md" ContentType="text/markdown"/>
  <Default Extension="vsixmanifest" ContentType="text/xml"/>
</Types>'''
destination = root / f"{package['name']}-{package['version']}.vsix"
with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as output:
    output.writestr("extension.vsixmanifest", manifest)

    output.writestr("[Content_Types].xml", types)

    for name in ("package.json", "extension.js", "README.md"):
        output.write(root / name, "extension/" + name)
print(destination)
