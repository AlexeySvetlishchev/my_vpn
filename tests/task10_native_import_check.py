"""Opt-in Linux/Qt import check with pinned official source, synthetic keys only.

Run in a disposable container with Qt6Core dev, g++, qrencode and zbar-tools:
  python3 -B tests/task10_native_import_check.py /upstream
This is an importer/codec/model check, NOT a physical-client connection test.
Only unreachable GUI branches and unrelated container implementations are stubbed.
No upstream implementation is vendored into this repository.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'scripts/task09'), str(ROOT/'scripts/task10'), str(ROOT/'tests')]
from task09_vault_test import VaultTests
from qr import profile_qr
from manager_formats import SERVER_DISPLAY_NAME

COMMIT = 'ac175c8a8147cfe56f98c8372ec17ea2ba00bb02'


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main(upstream):
    # A checkout is read-only input; nothing from it is installed on a VPS.
    assert subprocess.check_output(['git','-C',str(upstream),'rev-parse','HEAD']).decode().strip() == COMMIT
    def source(path):
        # Refuse edits to the exact upstream inputs used for compilation.
        blob = subprocess.check_output(['git','-C',str(upstream),'show',COMMIT+':'+path])
        text = (upstream/path).read_text()
        assert text == blob.decode().replace('\r\n', '\n')
        return text
    imports = source('client/core/controllers/selfhosted/importController.cpp')
    awg = source('client/core/models/protocols/awgProtocolConfig.cpp')
    native = source('client/core/models/selfhosted/nativeServerConfig.cpp')
    source('client/core/models/protocols/awgProtocolConfig.h')
    source('client/core/utils/constants/configKeys.h')
    prefix = r'''
#include <QtCore>
#include "core/models/protocols/awgProtocolConfig.h"
#include "core/utils/constants/configKeys.h"
enum class ConfigTypes { Invalid, Backup, Amnezia, WireGuard, Xray, OpenVpn, XraySettings };
enum class ErrorCode { NoError, ImportInvalidConfigError };
class ImportController {
public:
 struct ImportResult { QJsonObject config; ConfigTypes configType=ConfigTypes::Invalid; ErrorCode errorCode=ErrorCode::NoError; };
 ImportResult extractConfigFromQr(const QByteArray &data);
 ImportResult extractConfigFromData(const QString &,const QString &) { qFatal("unexpected GUI/raw branch"); return {}; }
};
bool rejectUnsupportedFormatVersion(ImportController::ImportResult &result) {
 if(result.config.value("format_version").toInt(0)>1) qFatal("unsupported format"); return false;
}
namespace amnezia {
enum class DockerContainer { None, Awg };
struct ContainerUtils {
 static DockerContainer containerFromString(const QString &s) { return s=="amnezia-awg"?DockerContainer::Awg:DockerContainer::None; }
};
struct ContainerConfig {
 static ContainerConfig fromJson(const QJsonObject &) { return {}; }
};
struct NativeServerConfig {
 QString description,displayName,hostName,dns1,dns2;
 QMap<DockerContainer,ContainerConfig> containers;
 DockerContainer defaultContainer;
 static NativeServerConfig fromJson(const QJsonObject &json);
};
}
'''
    cpp = prefix + function(imports, 'ConfigTypes checkConfigFormat(') + '\n'
    cpp += function(imports, 'ImportController::ImportResult ImportController::extractConfigFromQr(') + '\n'
    cpp += 'namespace amnezia {\n'
    for signature in ('AwgClientConfig AwgClientConfig::fromJson(',
                      'AwgServerConfig AwgServerConfig::fromJson(',
                      'AwgProtocolConfig AwgProtocolConfig::fromJson('):
        cpp += function(awg, signature) + '\n'
    cpp += function(native, 'NativeServerConfig NativeServerConfig::fromJson(') + '\n}\n'
    cpp += r'''
int main(int argc,char**argv) {
 QCoreApplication app(argc,argv);
 auto read=[](QString path) { QFile f(path); if(!f.open(QIODevice::ReadOnly)) qFatal("file"); return f.readAll(); };
 QByteArray uri=read(argv[1]),raw=read(argv[2]);
 if(!uri.startsWith("vpn://")) return 1;
 QByteArray encoded=uri.mid(6);
 QByteArray packed=QByteArray::fromBase64(encoded,QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals);
 QJsonObject fileJson=QJsonDocument::fromJson(qUncompress(packed)).object();
 auto qr=ImportController().extractConfigFromQr(encoded);
 if(qr.errorCode!=ErrorCode::NoError || qr.config!=fileJson || fileJson.isEmpty()) return 2;
 auto model=amnezia::NativeServerConfig::fromJson(qr.config);
 if(model.displayName!=QString::fromUtf8(argv[3]) || model.dns1!="10.203.253.1" || model.dns2!=model.dns1) return 3;
 auto container=qr.config.value("containers").toArray().at(0).toObject();
 auto awg=amnezia::AwgProtocolConfig::fromJson(container.value("awg").toObject());
 if(!awg.serverConfig.isThirdPartyConfig || !awg.clientConfig.has_value()) return 4;
 auto c=awg.clientConfig.value();
 if(c.nativeConfig.toUtf8()!=raw || c.port!=51821 || c.hostName!="137.22.146.212" || c.clientIp!="10.203.253.3/32") return 5;
 if(c.allowedIps!=QStringList{"0.0.0.0/0","::/0"} || c.mtu!="1280" || c.persistentKeepAlive!="25") return 6;
 if(c.initPacketJunkSize!="32" || c.cookieReplyPacketJunkSize!="32" || c.initPacketMagicHeader!="176321011-176321111") return 7;
 puts("official_qt_import_and_display_name: PASS");
 return 0;
}
'''
    fixture = VaultTests()
    fixture.setUp()
    try:
        raw, uri = fixture.named_pair()
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder/'check.cpp').write_text(cpp)
            (folder/'synthetic.vpn').write_bytes(uri)
            (folder/'synthetic.conf').write_bytes(raw)
            flags = subprocess.check_output(['pkg-config','--cflags','--libs','Qt6Core']).decode().split()
            subprocess.run(['g++','-std=c++17','-fPIC','-I'+str(upstream/'client'),str(folder/'check.cpp'),
                            '-o',str(folder/'check'),*flags],check=True)
            subprocess.run([str(folder/'check'),str(folder/'synthetic.vpn'),str(folder/'synthetic.conf'),SERVER_DISPLAY_NAME],check=True)
            (folder/'qr.png').write_bytes(profile_qr(uri[6:]))
            decoded = subprocess.check_output(['zbarimg','--quiet','--raw',str(folder/'qr.png')],stderr=subprocess.DEVNULL).rstrip(b'\n')
            assert decoded == uri[6:]
            print(json.dumps({'native_qr_scan_roundtrip':True,'source_commit':COMMIT,
                              'physical_device_import_tested':False}))
    finally:
        fixture.doCleanups()


if __name__ == '__main__':
    main(Path(sys.argv[1]))
