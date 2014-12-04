#!/usr/bin/env python
# -*- coding: utf-8 -*-
#  
#  UNIVERSIDADE DO VALE DO RIO DOS SINOS - UNISINOS
#  Disciplina de Segurança em Comércio Eletrônico
#  Professor Luciano Ignaczak
#  Ano: 2014 semestre 2
#  
#  Grupo: Grupo dos 4
#  Integrantes: Douglas Secco dos Santos, Vanessa Leite, Jonas Ferreira, Tiago Motta
#  Objetivo da tarefa : Recuperar o chain de certificados até a raíz a partir de um arquivo de certificado digital emitido para uma entidade final.
#  						O script deve identificar as informações do subject, do certificado da entidade emissora e todas as AC subordinadas assim como a raíz.
#						O script deve também informar se o certificado é confiável caso a entidade raíz seja confiável, para isso, o script deve receber por parâmetro
# 						o certificado a ser verificado e um container onde estão os certificados de AC raíz confiáveis. Caso o usuário não forneça o container, o padrão do sistema
# 						operacional (LINUX) será utilizado.
#
# Para funcionar, deve-se instalar as seguintes dependências:
#	Instalar o pip:
#   DEBIAN LIKE: apt-get install python-pip
#   REDHAT LIKE: yum install python-pip
#   
#   Instalar m2crypto:
#   bash$ pip install M2Crypto
# 	bash$ pip install pyOpenSSL
#
#	Instalar pycrypto:
# 	bash$ pip install pycrypto
#
# INSTRUÇÕES DE USO:
# bash$ python t5.py <certificado> [container]
# 
# Foram anexados certificados digitais, que podem ser usados como exemplo. 
# No diretório container foi adicionado um certificado raíz autêntico da Entrust,
# que pode ser utilizado para validar o certificado de usuário unisinos.br.crt. 
# O certificado digital commcorp.com.br.crt foi emitido por uma autoridade, portanto,
# caso o script seja executado sem um container específico, será utilizado o container padrão do SO que por sua vez,
# possui o certificado da autoridade certificadora relacionada ao certificado da commcorp.com.br. Se este mesmo certificado
# for usado em conjunto com o container, será informado que o certificado não é confiável, pois o certificado digital da autoridade certificadora
# não estará dentro deste diretório.
#
#
import hashlib
import M2Crypto as m2
from OpenSSL import SSL, crypto
from Crypto.Util import asn1
import ssl
import sys, os, datetime
import urllib2
from stat import *



revocation = None
lista_certificados=[]
status = False
chain = False

def ExtensoestoDict(cert):
    certificateExtensions = {}
    for index in range(cert.get_ext_count()):
        ext = cert.get_ext_at(index)
        certificateExtensions[ext.get_name()] = ext.get_value()
    return certificateExtensions

def BuscaCerts(container):
	achei = []
	try:
		dados = os.listdir(container)
		for arquivo in dados: 
			path=container+"/"+arquivo
			if S_ISREG(os.stat(path)[ST_MODE]):
				achei.append(arquivo)
		return achei
	except:
		pass

def GrabIssuerCrt(url):
	#print "URL: "+url
	buf = urllib2.urlopen(url).read()
	try:
		data = ssl.DER_cert_to_PEM_cert(buf)
		x509 = crypto.load_certificate(crypto.FILETYPE_PEM, data)
	except:
		x509 = crypto.load_certificate(crypto.FILETYPE_PEM,buf)

	x509ossl = crypto.dump_certificate(crypto.FILETYPE_PEM,x509)
	x509m2 = m2.X509.load_cert_string(x509ossl)
	return x509,x509ossl,x509m2

def ValidateSign(cacert,efcert):
	algoritmo=efcert.get_signature_algorithm()
	certificado_asn1=crypto.dump_certificate(crypto.FILETYPE_ASN1, efcert)
	der=asn1.DerSequence()
	der.decode(certificado_asn1)

	# der[0] - certificado
	# der[1] - algoritmo
	# der[2] - assinatura
	sign=asn1.DerObject()
	sign.decode(der[2])
	sig0=sign.payload
	# o primeiro byte é zero
	# http://msdn.microsoft.com/en-us/library/windows/desktop/bb540792(v=vs.85).aspx
	assinatura=sig0[1:]
	try:
		# certificado assinado pela ca fornecida
		crypto.verify(cacert, assinatura, der[0], algoritmo)
		return True 
	except:
		# certificado nao foi assinado por esta ca
		return False

def VerificarInfo(info):
	v1=hash(frozenset(info.items()))
	for mydict in reversed(lista_certificados):
		v2=hash(frozenset(mydict.items()))
		if v1==v2:
			return True
	return False

def CertificadoEmissor(certificado_m2):
	remotefile=None
	extensoes_certificado=ExtensoestoDict(certificado_m2)
	for k,v in extensoes_certificado.iteritems():
		if k == "authorityInfoAccess":
			componentes = v.split('\n')
			for item in componentes:
				if "CA Issuers" in item:
					remotefile=item.replace('CA Issuers - URI:','')
	return remotefile

def RemontarChain(arquivo,container):
	global status
	global chain
	info={}
	certificado = crypto.load_certificate(crypto.FILETYPE_PEM, file(arquivo).read())
	certificado_pem = crypto.dump_certificate(crypto.FILETYPE_PEM,certificado)
	certificado_m2 = m2.X509.load_cert_string(certificado_pem)

	subject = certificado.get_subject().get_components()

	for k, v in dict(subject).iteritems():
		info[k]=v
	if VerificarInfo(info) == False:
		lista_certificados.append(dict(info))
	info={}

	subject_hash=hashlib.md5(certificado.get_subject().der()).hexdigest() 
	emissor_hash=hashlib.md5(certificado.get_issuer().der()).hexdigest()

	# se nao for auto assinado:
	if emissor_hash != subject_hash:
		emissor_ptr=CertificadoEmissor(certificado_m2)
		emissor_cert_openssl,emissor_cert_str,emissor_cert_m2=GrabIssuerCrt(emissor_ptr)
		#res=ValidateSign(emissor_cert_openssl,certificado)
		emissor = emissor_cert_openssl.get_subject().get_components()
		for k, v in dict(emissor).iteritems():
			info[k]=v
		lista_certificados.append(dict(info))
		info={}

		found = BuscaCerts(container)
		#explorar o container
		for i in found:
			#
			# PARA MOSTRAR TODOS OS CERTIFICADOS ANALISADOS, DESCOMENTAR A LINHA ABAIXO:
			#print "certificado: " +i
			path = container + "/" + i 
			certificado_root = crypto.load_certificate(crypto.FILETYPE_PEM, file(path).read())
			res=ValidateSign(certificado_root,emissor_cert_openssl)
			if res == True:
				chain=True
				RemontarChain(path,container)

	else:
		if chain == True:
			status = True

	return True

def VerChain():
	loop=0
	for item in reversed(lista_certificados):
		loop+=1
		print "%s-------------------------------------------------------" %('\t'*loop)
		for k, v in item.iteritems():
			if k != "cert":
				print "%s %s: %s " %('\t'*loop,k,v)
		print "%s-------------------------------------------------------" %('\t'*loop)



def main():
	args=len(sys.argv)

	if args <2:
		print "%s <certificado do usuario> <diretorio contendo os certificados CA>" %sys.argv[0]
		print "\t Por padrao, será utilizado o diretório /etc/ssl/certs/ do sistema, caso o usuario nao forneca o parametro"

	if args == 3:
		print "[*] Container: %s" %str(sys.argv[2])
		RemontarChain(sys.argv[1],sys.argv[2])
	if args == 2:
		print "[*] Container: /etc/ssl/certs/"
		RemontarChain(sys.argv[1],'/etc/ssl/certs/')
	
	print "[*] A cadeia de certificados do arquivo selecionado:"
	if status == False:
		print "  - Este certificado não é confiável, pois não possui emissor relacionado no container de certificados confiáveis"
	else:
		print "  - Este certificado é confiável pois possui emissor relacionado no container de certificados confiáveis"
	VerChain()


if __name__ == "__main__":
	main()
