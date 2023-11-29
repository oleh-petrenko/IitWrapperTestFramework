import UIKit
import MobileCoreServices

class ReadPKViewController: UIViewController, UIPopoverPresentationControllerDelegate, UIDocumentPickerDelegate, UIPickerViewDataSource, UIPickerViewDelegate, UITextFieldDelegate {
    private let library: EUSignCPObjC = EUSignCPObjC.shared()
	private var pkKeyMediaTypes: NSArray?
	private var pkKeyMedias: NSArray?
    private var pkFileURI: URL?
	private var casPickerView: UIPickerView?
	private var pkKeyMediaPickerView: UIPickerView?
    
	static let KM_TYPE = "е.ключ ІІТ Алмаз-1К"
	
    @IBOutlet weak var caTextField: UITextField!
	@IBOutlet weak var pkKeyMediaTextField: UITextField!
	@IBOutlet weak var pkKeyMediaSelectButton: UIButton!
    @IBOutlet weak var pkFileTextField: UITextField!
    @IBOutlet weak var pkFileSelectButton: UIButton!
    @IBOutlet weak var pkPasswordTextField: UITextField!
    @IBOutlet weak var pkReadButton: UIButton!
      
	@IBOutlet weak var generatePKeyButton: UIButton!
	@IBOutlet weak var signDataButton: UIButton!
    
    var actionIndicator: UIActivityIndicatorView!
	
    override func viewDidLoad() {
        super.viewDidLoad()
        
        actionIndicator = UIActivityIndicatorView(frame: view.bounds)
        actionIndicator.center = view.center
        actionIndicator.style = UIActivityIndicatorView.Style.whiteLarge
        actionIndicator.backgroundColor = UIColor(red: 12/255, green: 35/255, blue: 73/255, alpha: 0.5)
        actionIndicator.isUserInteractionEnabled = false
        view.addSubview(actionIndicator)

        initCryptoLibrary()
      
        self.pkKeyMediaPickerView = createPickerViewForTextField(textField: self.pkKeyMediaTextField)
        self.casPickerView = createPickerViewForTextField(textField: self.caTextField)
    }

    @IBAction func selectPK(_ sender: Any) {
        let picker = UIDocumentPickerViewController.init(documentTypes: [String(kUTTypeData)], in: .open)
        picker.delegate = self
        self.present(picker, animated: true, completion: nil)
    }
	
	@IBAction func updateKeyMedia(_ sender: Any) {
        let queue = DispatchQueue(label: "queue")
		queue.async {
            DispatchQueue.main.sync {
                self.actionIndicator.startAnimating()
            }
            
            do {
				let kmTypeIndex = self.pkKeyMediaTypes?.index(of: ReadPKViewController.KM_TYPE)
				
				var keyMedias: NSArray? = nil
					
				try self.library.enumKeyMediaDevices(forType: kmTypeIndex!, devices:&keyMedias)
				
				DispatchQueue.main.sync {
					self.pkKeyMedias = keyMedias;
					self.pkKeyMediaTextField.text =
						self.pkKeyMedias!.count > 0 ?
						(self.pkKeyMedias![0] as! String) : ""
					
					self.pkPasswordTextField.isEnabled =
						self.pkKeyMedias!.count > 0 ||
						self.pkFileURI != nil
					self.pkReadButton.isHidden =
						self.pkKeyMedias!.count == 0 &&
						self.pkFileURI == nil
					self.pkKeyMediaTextField.isEnabled =
						self.pkKeyMedias!.count > 1
				}
			} catch {
				NSLog(error.localizedDescription)
				DispatchQueue.main.sync {
					self.showAlert(message: "Виникла помилка при оновленні списку ключових носіїв. " +
						"Опис помилки: " + error.localizedDescription, handler: nil)
				}
			}

            DispatchQueue.main.sync {
                self.actionIndicator.stopAnimating()
            }
        }
    }
    
//    @IBAction func readPK(_ sender: Any) {
//        let caIssuerCN = self.caTextField.text!
//        if caIssuerCN.isEmpty {
//            showAlert(message: "Не вказано ЦСК", handler: {
//                _ in
//                self.caTextField.becomeFirstResponder()
//            })
//            
//            return
//        }
//        
//		let pkFileName = self.pkFileTextField.text!
//		let pkKeyMediaName = self.pkKeyMediaTextField.text!
//		
//		if pkFileName.isEmpty && pkKeyMediaName.isEmpty {
//            showAlert(message: "Не обрано носій або файл з ос. ключем", handler: {
//                _ in
//				self.pkKeyMediaTextField.becomeFirstResponder()
//            })
//            
//            return
//        }
//        
//        let password = self.pkPasswordTextField.text!
//        if password.isEmpty {
//            showAlert(message: "Не вказано пароль до ос. ключа", handler: {
//                _ in
//                self.pkPasswordTextField.becomeFirstResponder()
//            })
//            return
//        }
//
//		let appDelegate = UIApplication.shared.delegate as! AppDelegate
//
//        let queue = DispatchQueue(label: "queue")
//        queue.async {
//            DispatchQueue.main.sync {
//                self.actionIndicator.startAnimating()
//            }
//
//            do {
//				let isReadPKey = appDelegate.pkContext == nil
//                if isReadPKey {
//					if !pkFileName.isEmpty {
//						let privateKey = self.readFile(fileURL: self.pkFileURI!)!
//
//						try self.library.ctxReadPrivateKeyBinary(appDelegate.context!,
//							privateKey: privateKey, password: password,
//							certificates: nil, caIssuerCN: caIssuerCN,
//							privateKeyContext: &appDelegate.pkContext)
//                        
//                        //////////
//                        var resultArray: NSArray? = nil
//                        try self.library.ctxGetOwnCertificates(appDelegate.pkContext!, certificates: &resultArray)
//                        print(resultArray)
//                        
//                        if let resultArray = resultArray as? [EUCertificate], let certificate = resultArray.first {
//                            let infoEx = certificate.infoEx
//                            print(infoEx)
//                        }
//                        //////////
//					} else {
//						let typeIndex = self.pkKeyMediaTypes?.index(of: ReadPKViewController.KM_TYPE)
//						let deviceIndex = self.pkKeyMedias?.index(of:pkKeyMediaName)
//						
//						try self.library.ctxReadPrivateKey(appDelegate.context!,
//							typeIndex: typeIndex!, deviceIndex: deviceIndex!,
//							password: password, certificates: nil, caIssuerCN: caIssuerCN,
//							privateKeyContext: &appDelegate.pkContext)
//					}
//                } else {
//                    self.library.ctxFreePrivateKey(appDelegate.pkContext!)
//					appDelegate.pkContext = nil
//                }
//
//                DispatchQueue.main.sync {
//					self.pkReadButton.setTitle(isReadPKey ? "Зтерти" : "Зчитати", for: UIControl.State.normal)
//                    self.caTextField.isEnabled = !isReadPKey
//					self.pkKeyMediaTextField.isEnabled = !isReadPKey;
//					self.pkKeyMediaSelectButton.isHidden = isReadPKey;
//                    self.pkFileSelectButton.isHidden = isReadPKey
//                    self.pkPasswordTextField.isEnabled = !isReadPKey
//					
//					self.signDataButton.isHidden = !isReadPKey
//                    
//                    self.showAlert(message: "Особистий ключ успішно зчитано. " +
//                        "Можна виконати підпис даних або зтерти ключ та зчитати інший", handler: nil)
//                }
//            } catch {
//                NSLog(error.localizedDescription)
//                DispatchQueue.main.sync {
//                    self.showAlert(message: "Виникла помилка при зчитуванні ос. ключа. " +
//                        "Опис помилки: " + error.localizedDescription, handler: nil)
//                }
//            }
//
//            DispatchQueue.main.sync {
//                self.actionIndicator.stopAnimating()
//            }
//        }
//    }
       
    @IBAction func readPK(_ sender: Any) {
        let caIssuerCNs = self.library.getCAs()

        let pkFileName = self.pkFileTextField.text!
        let pkKeyMediaName = self.pkKeyMediaTextField.text!
        
        if pkFileName.isEmpty && pkKeyMediaName.isEmpty {
            showAlert(message: "Не обрано носій або файл з ос. ключем", handler: {
                _ in
                self.pkKeyMediaTextField.becomeFirstResponder()
            })
            return
        }
        
        let password = self.pkPasswordTextField.text!
        if password.isEmpty {
            showAlert(message: "Не вказано пароль до ос. ключа", handler: {
                _ in
                self.pkPasswordTextField.becomeFirstResponder()
            })
            return
        }

        let appDelegate = UIApplication.shared.delegate as! AppDelegate

        let queue = DispatchQueue(label: "queue")
        queue.async {
            DispatchQueue.main.sync {
                self.actionIndicator.startAnimating()
            }

            for caIssuerCN in caIssuerCNs {
                do {
                    let isReadPKey = appDelegate.pkContext == nil
                    if isReadPKey {
                        if !pkFileName.isEmpty {
                            let privateKey = self.readFile(fileURL: self.pkFileURI!)!

                            try self.library.ctxReadPrivateKeyBinary(appDelegate.context!,
                                privateKey: privateKey, password: password,
                                                                     certificates: nil, caIssuerCN: caIssuerCN.issuerCNs[0],
                                privateKeyContext: &appDelegate.pkContext)
                        } else {
                            let typeIndex = self.pkKeyMediaTypes?.index(of: ReadPKViewController.KM_TYPE)
                            let deviceIndex = self.pkKeyMedias?.index(of: pkKeyMediaName)
                            
                            try self.library.ctxReadPrivateKey(appDelegate.context!,
                                typeIndex: typeIndex!, deviceIndex: deviceIndex!,
                                password: password, certificates: nil, caIssuerCN: caIssuerCN.issuerCNs[0],
                                privateKeyContext: &appDelegate.pkContext)
                        }

                        if appDelegate.pkContext != nil {
                            print("SUCCESS !!!")
                            DispatchQueue.main.sync {
                                // Обновление UI после выполнения операции
                                self.actionIndicator.stopAnimating()
                                self.pkReadButton.setTitle(appDelegate.pkContext != nil ? "Зтерти" : "Зчитати", for: .normal)
                                self.caTextField.isEnabled = appDelegate.pkContext == nil
                                self.pkKeyMediaTextField.isEnabled = appDelegate.pkContext == nil
                                self.pkKeyMediaSelectButton.isHidden = appDelegate.pkContext != nil
                                self.pkFileSelectButton.isHidden = appDelegate.pkContext != nil
                                self.pkPasswordTextField.isEnabled = appDelegate.pkContext == nil
                                self.signDataButton.isHidden = appDelegate.pkContext == nil

                                let message = appDelegate.pkContext != nil ? "Особистий ключ успішно зчитано. Можна виконати підпис даних або зтерти ключ та зчитати інший" : "Не вдалося зчитати ключ"
                                self.showAlert(message: message, handler: nil)
                            }
                            return // Успешно инициализировано, выходим из цикла
                        }
                    } else {
                        self.library.ctxFreePrivateKey(appDelegate.pkContext!)
                        appDelegate.pkContext = nil
                    }
                } catch {
//                    NSLog(error.localizedDescription)
//                    DispatchQueue.main.sync {
//                        self.showAlert(message: "Виникла помилка при зчитуванні ос. ключа. " +
//                            "Опис помилки: " + error.localizedDescription, handler: nil)
//                    }
                }
            }

            DispatchQueue.main.sync {
                // Обновление UI после выполнения операции
                self.actionIndicator.stopAnimating()
                self.pkReadButton.setTitle(appDelegate.pkContext != nil ? "Зтерти" : "Зчитати", for: .normal)
                self.caTextField.isEnabled = appDelegate.pkContext == nil
                self.pkKeyMediaTextField.isEnabled = appDelegate.pkContext == nil
                self.pkKeyMediaSelectButton.isHidden = appDelegate.pkContext != nil
                self.pkFileSelectButton.isHidden = appDelegate.pkContext != nil
                self.pkPasswordTextField.isEnabled = appDelegate.pkContext == nil
                self.signDataButton.isHidden = appDelegate.pkContext == nil

                let message = appDelegate.pkContext != nil ? "Особистий ключ успішно зчитано. Можна виконати підпис даних або зтерти ключ та зчитати інший" : "Не вдалося зчитати ключ"
                self.showAlert(message: message, handler: nil)
            }
        }
    }

    
    
    
    
    
    
    
    
    func showAlert(message: String, handler:((UIAlertAction)->Void)?) {
        let alert = UIAlertController(title: "Повідомлення оператору", message: message, preferredStyle: .alert)

        alert.addAction(UIAlertAction(title: "OK", style: .default, handler: handler))

        self.present(alert, animated: true)
    }
    
    func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {
        return false
    }
	
	func createPickerViewForTextField(textField: UITextField) -> UIPickerView {
		let pickerView = UIPickerView()
		pickerView.delegate = self
		pickerView.dataSource = self
		textField.inputView = pickerView
		textField.delegate = self
		
		let toolBar = UIToolbar()
		toolBar.sizeToFit()
		let button = UIBarButtonItem(title: "Обрати", style: .plain, target: self, action: #selector(self.dismissPickerView))
		toolBar.setItems([button], animated: true)
		toolBar.isUserInteractionEnabled = true
		textField.inputAccessoryView = toolBar
		
		return pickerView
	}
	
	@objc func dismissPickerView() {
		view.endEditing(true)
	}
    
    func numberOfComponents(in pickerView: UIPickerView) -> Int {
        return 1
    }

    func pickerView(_ pickerView: UIPickerView, numberOfRowsInComponent component: Int) -> Int {
		if pickerView == pkKeyMediaPickerView {
			return pkKeyMedias!.count
		} else if pickerView == casPickerView {
			let CAs = self.library.getCAs()
			return CAs.count
		} else {
			return 0
		}
    }

    func pickerView(_ pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String? {
		if pickerView == pkKeyMediaPickerView {
			return pkKeyMedias![row] as? String
		} else if pickerView == casPickerView {
			let CAs = self.library.getCAs()
			return CAs[row].issuerCNs[0]
		} else {
			return ""
		}
    }

    func pickerView(_ pickerView: UIPickerView, didSelectRow row: Int, inComponent component: Int){
		if pickerView == pkKeyMediaPickerView {
			let keyMedia = pkKeyMedias![row] as? String
			self.pkKeyMediaTextField.text = keyMedia
			self.view.endEditing(true)
		} else if pickerView == casPickerView {
			let CAs = self.library.getCAs()
			self.caTextField.text = CAs[row].issuerCNs[0]
			self.view.endEditing(true)
		} else {
			self.view.endEditing(true)
		}
    }
    
    func readFileFromBundle(fileName: String) throws -> Data? {
        guard let fileURL = URL.init(string: fileName),
            let url = Bundle.main.url(
                forResource: fileURL.deletingPathExtension().path,
                withExtension: fileURL.pathExtension) else {
            return nil
        }
        return try Data.init(contentsOf: url)
    }
    
    func readFile(fileURL: URL) -> Data? {
        let success = fileURL.startAccessingSecurityScopedResource()
        var data: Data?
        let fileCoordinator = NSFileCoordinator.init()

        fileCoordinator.coordinate(readingItemAt: fileURL, options: .init(rawValue: 0), error: nil, byAccessor: { url in
            data = try? Data.init(contentsOf: url)
        })
        
        if success {
            fileURL.stopAccessingSecurityScopedResource()
        }
        
        return data
    }
    
    func saveFile(fileName: String, data: Data) {
        let tmpDir = FileManager.default.temporaryDirectory
        let tmpFile = tmpDir.appendingPathComponent(fileName)
        
        do {
            try? FileManager.default.removeItem(at: tmpFile)
            try data.write(to: tmpFile)
            let activityVC = UIActivityViewController(activityItems: [tmpFile], applicationActivities: nil)
            self.present(activityVC, animated: true, completion: nil)
        } catch {
            NSLog(error.localizedDescription)
        }
    }
    
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        let fileURL = urls.first
        if fileURL == nil {
            pkFileTextField.text = ""
            pkPasswordTextField.text = ""
            pkPasswordTextField.isEnabled = false
            pkReadButton.isHidden = true
            self.pkFileURI = nil
            return
        }

        self.pkFileURI = fileURL
        pkFileTextField.text = fileURL?.absoluteString
        pkPasswordTextField.isEnabled = true
        pkReadButton.isHidden = false
    }
    
    func initCryptoLibrary() {
        let queue = DispatchQueue(label: "queue")
		var appDelegate: AppDelegate!
		
        queue.async {
            if self.library.isInitialized() {
                return
            }
            
            DispatchQueue.main.sync {
                self.actionIndicator.startAnimating()
				
				appDelegate = (UIApplication.shared.delegate as! AppDelegate)
            }

            do {
                let casData = try self.readFileFromBundle(fileName: "CAs.json")
                let certificatesData = try self.readFileFromBundle(fileName: "CACertificates.p7b")

                try self.library.initialize(casData!, certificates: certificatesData!)
				
				try self.library.ctxCreate(&appDelegate.context)
                
                let cas = self.library.getCAs()
		
				var keyMediaTypes: NSArray? = nil
					
				try self.library.enumKeyMediaTypes(&keyMediaTypes)
				
				self.pkKeyMediaTypes = keyMediaTypes
        
				DispatchQueue.main.sync {
					self.caTextField.isEnabled = true
                    self.caTextField.text = cas.first?.issuerCNs.first

                    self.pkKeyMediaSelectButton.isHidden = false
					
					self.generatePKeyButton.isEnabled = true;
				}
			} catch {
                NSLog(error.localizedDescription)
                DispatchQueue.main.sync {
                    self.showAlert(message: "Виникла помилка при ініціалізації криптографічної бібліотеки. " +
                        "Опис помилки: " + error.localizedDescription, handler: nil)
                }
            }

            DispatchQueue.main.sync {
                self.actionIndicator.stopAnimating()
            }
        }
    }
}

