import PyKCS11
from cryptography import x509   
from cryptography.hazmat.primitives.asymmetric import padding as pd
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID


lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots =pkcs11.getSlotList()
for slot in slots:
    print(pkcs11.getTokenInfo(slot))
#slot=pkcs11.getSlotList(tokenPresent=Tru)[0]
session=pkcs11.openSession(slot)
all_attributes = list(PyKCS11.CKA.keys())
all_attributes = [e for e in all_attributes if isinstance(e, int)]
obj = session.findObjects([(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0]
attributes = session.getAttributeValue(obj, all_attributes)
attributes = dict(zip(map(PyKCS11.CKA.get, all_attributes), attributes))
authentication_cert = x509.load_der_x509_certificate(bytes(attributes['CKA_VALUE']))

#certificate=x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']))
cc_num = authentication_cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
print(cc_num[0].value)

private_key_cc = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None) 
text=b'umteste'
signature = bytes(session.sign(private_key_cc, text, mech))
print(authentication_cert.public_key().verify(signature,text, pd.PKCS1v15(), hashes.SHA1()))




