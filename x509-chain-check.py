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
import ssl
import sys, os, re, datetime

class certificado(object):
	def __init__(self):
		self.len=0
	data=None
	data_hash=None


revocation = None
lista_certificados=[]
status = False


def BuscaCerts (string,container):
	achei = []
	try:
		dados = os.listdir(container)
		for linha in dados: 
			if re.match(string, linha):
				achei.append(linha)	
		return achei
	except:
		pass

def RemontarChain(arquivo,container):
	global status
	d1={}
	d2={}
	
	x509 = crypto.load_certificate(crypto.FILETYPE_PEM, file(arquivo).read())
	emissor = x509.get_issuer().get_components()
	x509pem = crypto.dump_certificate(crypto.FILETYPE_PEM,x509)
	x509m2 = m2.X509.load_cert_string(x509pem)
	d1["cert"]=x509m2

	for k, v in dict(emissor).iteritems():
		d1[k]=v
	emissor_hash=hashlib.md5(x509.get_issuer().der()).hexdigest()

	d1["hashemissor"]=emissor_hash

	subject = x509.get_subject().get_components()
	for k, v in dict(subject).iteritems():
		d2[k]=v	

	subject_hash=hashlib.md5(x509.get_subject().der()).hexdigest()
	d2["isshash"]=subject_hash
	
	if emissor_hash != subject_hash:
		lista_certificados.append(d2)
		lista_certificados.append(d1)
		
		cnemissor = dict(x509.get_issuer().get_components())['CN']
		found = BuscaCerts((cnemissor.split(' ')[0] + '*'),container)

		#explorar o container
		for i in found:
			f = file('{0}/{1}'.format(container, i), 'rb').read()
			# PEGA A CHAVE PUBLICA DO CERTIFICADO
			root_signature = (m2.X509.load_cert_string(f)).get_pubkey()
			try:
				# COMPARA AS CHAVES DOS CERTIFICADOS PARA DETECTAR SE O ROOT EH AUTENTICO
				m2cert = m2.X509.load_cert_string(crypto.dump_certificate(crypto.FILETYPE_PEM, x509))
				if m2cert.verify(root_signature) == 0:
					# AS ASSINATURAS ESTAO BATENDO !!!
					# agora faz a chamada recursiva para capturar informacoes do certificado raiz
					cobj=container+"/"+i
					RemontarChain(cobj,container)
					status = True
					break
			except:
				pass
			#except Exception, j:
			#	print j

	else:
		lista_certificados.append(d1)
	return True

def VerChain():
	loop=0
	for item in reversed(lista_certificados):
		loop+=1
		print "%s-------------------------------------------------------" %('\t'*loop)
		for k, v in item.iteritems():
			if k != "cert":
				print "%s %s: %s " %('\t'*loop,k,v)
		for k, v in item.iteritems():
			if k == "cert":
				print "Certificado: "
				print "%s %s" %('\t'*loop,v.as_pem())
		print "%s-------------------------------------------------------" %('\t'*loop)



def main():
	if len(sys.argv) <2:
		print "%s <certificado do usuario> <diretorio contendo os certificados CA>" %sys.argv[0]
		print "\t Por padrao, será utilizado o diretório /etc/ssl/certs/ do sistema, caso o usuario nao forneca o parametro"


	try: 
		print "[*] Container: %s" %str(sys.argv[2])
		RemontarChain(sys.argv[1],sys.argv[2])
	except:
		print "[*] Container: /etc/ssl/certs/"
		RemontarChain(sys.argv[1],'/etc/ssl/certs/')
	print "[*] A cadeia de certificados do arquivo selecionado:"
	if not status:
		print "  - Este certificado não é confiável, pois não possui emissor relacionado no container de certificados confiáveis"
	else:
		print "  - Este certificado é confiável pois possui emissor relacionado no container de certificados confiáveis"
	VerChain()


if __name__ == "__main__":
	main()
