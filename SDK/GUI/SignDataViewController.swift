import UIKit
import MobileCoreServices

enum SignDataTestError: Error {
	case testError(String)
}

class SignDataViewController: UIViewController {
	private let library: EUSignCPObjC = EUSignCPObjC.shared()
	@IBOutlet weak var externalSwitch: UISwitch!
	@IBOutlet weak var dataTextView: UITextView!
	@IBOutlet weak var signatureTextView: UITextView!
	@IBOutlet weak var signButton: UIButton!
	@IBOutlet weak var verifyButton: UIButton!
    
    var actionIndicator: UIActivityIndicatorView!
	
	func addDoneButtonOnKeyboard(textView: UITextView){
			let doneToolbar: UIToolbar = UIToolbar(frame: CGRect.init(x: 0, y: 0, width: UIScreen.main.bounds.width, height: 50))
			doneToolbar.barStyle = .default

			let flexSpace = UIBarButtonItem(barButtonSystemItem: .flexibleSpace, target: nil, action: nil)
			let done: UIBarButtonItem = UIBarButtonItem(title: "Done", style: .done, target: self, action: #selector(self.doneButtonAction))

			let items = [flexSpace, done]
			doneToolbar.items = items
			doneToolbar.sizeToFit()

			textView.inputAccessoryView = doneToolbar
		}

		@objc func doneButtonAction(){
			dataTextView.resignFirstResponder()
		}
	
	override func viewDidLoad() {
		super.viewDidLoad()
		
        
        actionIndicator = UIActivityIndicatorView(frame: view.bounds)
        actionIndicator.center = view.center
        actionIndicator.style = UIActivityIndicatorView.Style.whiteLarge
        actionIndicator.backgroundColor = UIColor(red: 12/255, green: 35/255, blue: 73/255, alpha: 0.5)
        actionIndicator.isUserInteractionEnabled = false
        view.addSubview(actionIndicator)

		self.dataTextView.addDoneButton(title: "Done", target: self, selector: #selector(hideKeyboard(sender:)))
        
        self.verifyButton.isHidden = true
	}

	@objc func hideKeyboard(sender: Any) {
		self.view.endEditing(true)
	}
	
	@IBAction func signData(_ sender: Any) {
		let isExternal = self.externalSwitch.isOn
		
		let dataString = self.dataTextView.text!
		if dataString.isEmpty {
			showAlert(message: "Не вказано дані для підпису", handler: {
				_ in
				self.dataTextView.becomeFirstResponder()
			})
			
			return
		}
		
		self.signatureTextView.text = ""
		let data = dataString.data(using: .utf8)
		let appDelegate = UIApplication.shared.delegate as! AppDelegate

		let queue = DispatchQueue(label: "queue")
		queue.async {
            DispatchQueue.main.sync {
                self.actionIndicator.startAnimating()
            }

            do {
				var signature: NSData?
				try self.library.ctxSignData(appDelegate.pkContext!,
					signAlgo: EUCtxSignAlgoDSTU4145WithGOST34311,
					data: data!, external: isExternal, appendCert: true, signature: &signature)
 
                var signInfo: EUSignInfo?
                try self.library.verifyData(data!, sign: 0, signature: signature! as Data, signInfo: &signInfo)
                
                
                
                
                print(signInfo!)
                
				DispatchQueue.main.sync {
					self.signatureTextView.text = signature?.base64EncodedString()
				
                    self.showAlert(message: "Дані успішно підписано", handler: nil)
                    
                    self.verifyButton.isHidden = false
                }
			} catch {
				NSLog(error.localizedDescription)
				DispatchQueue.main.sync {
					self.showAlert(message: "Виникла помилка при підписі даних. " +
						"Опис помилки: " + error.localizedDescription, handler: nil)
				}
			}

            DispatchQueue.main.sync {
                self.actionIndicator.stopAnimating()
            }
        }
	}
	
	@IBAction func verifyData(_ sender: Any) {
		let isExternal = self.externalSwitch.isOn
		var dataString = ""
		var signatureString: String
		
		if isExternal {
			dataString = self.dataTextView.text!
			if dataString.isEmpty {
				showAlert(message: "Не вказано дані для перевірки підпису", handler: {
					_ in
					self.dataTextView.becomeFirstResponder()
				})
				
				return
			}
		}
		
		signatureString = self.signatureTextView.text!
		if signatureString.isEmpty {
			showAlert(message: "Не вказано підпис", handler: {
				_ in
				self.signatureTextView.becomeFirstResponder()
			})
			
			return
		}
		
		let data = isExternal ? dataString.data(using: .utf8) : nil
		let signature = Data(base64Encoded: signatureString, options: .ignoreUnknownCharacters)
		if !isExternal {
			self.dataTextView.text = ""
		}

		let queue = DispatchQueue(label: "queue")
		queue.async {
            DispatchQueue.main.sync {
                self.actionIndicator.startAnimating()
            }

            do {
				var verifiedData: NSData?
				var signInfo: EUSignInfo?

				if isExternal {
					try self.library.verifyData(data!, sign: 0, signature: signature!, signInfo: &signInfo)
				} else {
					try self.library.verifyDataInternal(0, signature: signature! as Data, data: &verifiedData, signInfo: &signInfo)
				}

				DispatchQueue.main.sync {
					if !isExternal {
						self.dataTextView.text = String(decoding: verifiedData!, as: UTF8.self)
					}
					
					self.showAlert(message: "Підпис успішно перевірено. " +
						"Інформація про підписувача: " + signInfo!.subjCN, handler: nil)
				}
			} catch {
				NSLog(error.localizedDescription)
				DispatchQueue.main.sync {
					self.showAlert(message: "Виникла помилка при перевірці підпису даних. " +
						"Опис помилки: " + error.localizedDescription, handler: nil)
				}
			}

            DispatchQueue.main.sync {
                self.actionIndicator.stopAnimating()
            }
		}
	}
	
	@IBAction func signDataTest(_ sender: Any) {
		let appDelegate = UIApplication.shared.delegate as! AppDelegate
		
		let queue = DispatchQueue(label: "queue")
		queue.async {
			DispatchQueue.main.sync {
				self.actionIndicator.startAnimating()
			}

			do {
				try self.makeTestCOMSignaturesInternal(context: appDelegate.context!, pkContext:appDelegate.pkContext!)
 
				DispatchQueue.main.sync {
					self.showAlert(message: "Тестування функцій підпису даних завершено успішно", handler: nil)
				}
			} catch {
				NSLog(error.localizedDescription)
				DispatchQueue.main.sync {
					self.showAlert(message: "Виникла помилка при тестуванні функцій підпису даних. " +
						"Опис помилки: " + error.localizedDescription, handler: nil)
				}
			}

			DispatchQueue.main.sync {
				self.actionIndicator.stopAnimating()
			}
		}
	}
	
	func makeTestCOMSignaturesInternal(context: EUContext, pkContext: EUPrivateKeyContext) throws {
		var certificates: NSArray?
		let data: Data? = "Data to sign".data(using: .utf8)
		var hash: NSData?
		var unsignedSigner: NSData?
		var attrsHash: NSData?
		var signValue: NSData?
		var signer: NSData?
		var signValueHash: NSData?
		var tsp: NSData?
		let ocspResponses = [] as NSMutableArray
		var ocspResponse: NSData?
		var caCertificates: NSArray?
		var revocationReferencesAttr: NSData?
		var revocationValuesAttr: NSData?
		var certificateReferencesAttr: NSData?
		var certificateValuesAttr: NSData?
		var sign: NSData?
		var verifiedData: NSData?
		var signInfo: EUSignInfo?
		
		try self.library.ctxGetOwnCertificates(pkContext, certificates: &certificates)
		
		for certificate in (certificates as! [EUCertificate]) {
			if (certificate.infoEx.keyUsageType.rawValue & EUKeyUsageDigitalSignature.rawValue == 0) &&
				(certificate.infoEx.keyUsageType.rawValue & EUKeyUsageNonRepudation.rawValue == 0) {
				continue
			}
			
			var hashAlgo: EUCtxHashAlgo
			var signAlgo: EUCtxSignAlgo
			
			switch certificate.infoEx.publicKeyType
			{
			case EUPubKeyDSTU4145:
				hashAlgo = EUCtxHashAlgoGOST34311
				signAlgo = EUCtxSignAlgoDSTU4145WithGOST34311
				
			case EUPubKeyRSA:
				hashAlgo = EUCtxHashAlgoSHA256
				signAlgo = EUCtxSignAlgoRSAWithSHA
			
			case EUPubKeyECDSA:
				hashAlgo = EUCtxHashAlgoSHA256
				signAlgo = EUCtxSignAlgoECDSAWithSHA
				
			default:
				continue
			}
			
			try self.library.ctxHashData(context, hashAlgo: hashAlgo, certificate: nil, data: data!, hash: &hash)
			
			try self.library.createSignerBegin(certificate.data, hash: hash! as Data, signer: &unsignedSigner, attrsHash: &attrsHash)
			try self.library.ctxGetSignValue(pkContext, signAlgo: signAlgo, hash: attrsHash! as Data, signValue: &signValue)
			try self.library.createSignerEnd(unsignedSigner! as Data, signarure: signValue! as Data, signer: &signer)
			
			try self.library.ctxHashData(context, hashAlgo: hashAlgo, certificate: nil, data: signValue! as Data, hash: &signValueHash)
			try self.library.getTSP(hashAlgo, hash: signValueHash! as Data, byAccessInfo: certificate.infoEx.tspAccessInfo, accessInfoPort: "80", tsp: &tsp)
			try self.library.appendSignerUnsignedAttribute(signer! as Data, attrOID: "1.2.840.113549.1.9.16.2.14", attrValue: tsp! as Data, signer: &signer)
			
			try self.library.getCertificateChain(certificate.data, caCertificates: &caCertificates)
			
			try self.library.getOCSPResponse(certificate.data, byAccessInfo: certificate.infoEx.ocspAccessInfo, accessInfoPort: "80", ocspResponse: &ocspResponse)
			ocspResponses.add(ocspResponse!)
			try self.library.createRevocationInfoAttributes(caCertificates!.count + 1, ocspResponses: ocspResponses as! [Data], revocationReferencesAttr: &revocationReferencesAttr, revocationValuesAttr: &revocationValuesAttr)
			try self.library.appendSignerUnsignedAttribute(signer! as Data, attrOID: "1.2.840.113549.1.9.16.2.22", attrValue: revocationReferencesAttr! as Data, signer: &signer)
			try self.library.appendSignerUnsignedAttribute(signer! as Data, attrOID: "1.2.840.113549.1.9.16.2.24", attrValue: revocationValuesAttr! as Data, signer: &signer)
			
			try self.library.createCACertificateInfoAttributes(caCertificates as! [Data], certificateReferencesAttr: &certificateReferencesAttr, certificateValuesAttr: &certificateValuesAttr)
			try self.library.appendSignerUnsignedAttribute(signer! as Data, attrOID: "1.2.840.113549.1.9.16.2.21", attrValue: certificateReferencesAttr! as Data, signer: &signer)
			try self.library.appendSignerUnsignedAttribute(signer! as Data, attrOID: "1.2.840.113549.1.9.16.2.23", attrValue: certificateValuesAttr! as Data, signer: &signer)
			
			try self.library.createEmptySign(data!, sign: &sign)
			try self.library.appendSigner(signer! as Data, certificate: certificate.data, previousSign: sign! as Data, sign: &sign)
			
			try self.library.verifyDataInternal(0, signature: sign! as Data, data: &verifiedData, signInfo: &signInfo)
		}
	}

	func showAlert(message: String, handler:((UIAlertAction)->Void)?) {
		let alert = UIAlertController(title: "Повідомлення оператору", message: message, preferredStyle: .alert)

		alert.addAction(UIAlertAction(title: "OK", style: .default, handler: handler))

		self.present(alert, animated: true)
	}
}
