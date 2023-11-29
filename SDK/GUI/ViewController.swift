import UIKit
import MobileCoreServices


class ReadPKViewController: UIViewController, UIPopoverPresentationControllerDelegate, UIDocumentPickerDelegate, UIPickerViewDataSource, UIPickerViewDelegate, UITextFieldDelegate {
    private let library: EUSignCPObjC = EUSignCPObjC.shared()
    private var pkFileURI: URL?
    
    @IBOutlet weak var caTextField: UITextField!
    @IBOutlet weak var pkFileTextField: UITextField!
    @IBOutlet weak var pkFileSelectButton: UIButton!
    @IBOutlet weak var pkPasswordTextField: UITextField!
    @IBOutlet weak var pkReadButton: UIButton!
    
    @IBOutlet weak var scNameTextField: UITextField!
    @IBOutlet weak var scPortTextField: UITextField!
    @IBOutlet weak var scGateAddressTextField: UITextField!
    @IBOutlet weak var scGatePortTextField: UITextField!
    @IBOutlet weak var scStartButton: UIButton!
            
    @IBAction func selectPK(_ sender: Any) {
        let picker = UIDocumentPickerViewController.init(documentTypes: [String(kUTTypeData)], in: .open)
        picker.delegate = self
        self.present(picker, animated: true, completion: nil)
    }
    
    @IBAction func readPK(_ sender: Any) {
        let caIssuerCN = self.caTextField.text!
        if caIssuerCN.isEmpty {
            showAlert(message: "Не вказано ЦСК", handler: {
                _ in
                self.caTextField.becomeFirstResponder();
            });
            
            return;
        }
        
        if let name = self.pkFileTextField.text, name.isEmpty {
            showAlert(message: "Не вказано файл з ос. ключем", handler: {
                _ in
                self.pkFileTextField.becomeFirstResponder();
            });
            
            return;
        }
        
        let password = self.pkPasswordTextField.text!
        if password.isEmpty {
            showAlert(message: "Не вказано пароль до ос. ключа", handler: {
                _ in
                self.pkPasswordTextField.becomeFirstResponder();
            });
            return;
        }

        let queue = DispatchQueue(label: "queue")
        queue.async {
            do {
                let isReadPKey = !self.library.isPrivateKeyReaded()
                if isReadPKey {
                    let privateKey = self.readFile(fileURL: self.pkFileURI!)!
                    
                    try self.library.readPrivateKeyBinary(
                        privateKey, password: password,
                        certificates: nil, caIssuerCN: caIssuerCN)
					
					let data = privateKey
					var signature: NSData?
					var verifiedData: NSData?
					var signInfo: EUSignInfo?
					
					var keyMedias: NSArray? = nil
					
					try self.library.enumKeyMediaTypes(&keyMedias)

					try self.library.sign(data, external:false, signature:&signature)
					try self.library.verifyDataInternal(0, signature: signature! as Data, data: &verifiedData, signInfo:&signInfo)
					try self.library.sign(data, external:false, signature:&signature)
                } else {
                    self.library.scClientStop()
                    self.library.resetPrivateKey()
                }

                DispatchQueue.main.sync {
                    self.pkReadButton.titleLabel?.text = isReadPKey ? "Зтерти" : "Зчитати"
                    self.caTextField.isEnabled = !isReadPKey
                    self.pkFileSelectButton.isEnabled = !isReadPKey
                    self.pkPasswordTextField.isEnabled = !isReadPKey
    
                    self.scStartButton.isEnabled = isReadPKey
                    self.scNameTextField.isEnabled = isReadPKey
                    self.scPortTextField.isEnabled = isReadPKey
                    self.scGateAddressTextField.isEnabled = isReadPKey
                    self.scGatePortTextField.isEnabled = isReadPKey
                    self.scStartButton.titleLabel?.text = "Запустити"
                }
            } catch {
                NSLog(error.localizedDescription)
                DispatchQueue.main.sync {
                    self.showAlert(message: "Виникла помилка при зчитуванні ос. ключа. " +
                        "Опис помилки: " + error.localizedDescription, handler: nil)
                }
            }
        }
    }
    
    @IBAction func startSC(_ sender: Any) {
        if let name = scNameTextField.text, name.isEmpty {
            showAlert(message: "Не вказано ім'я з'єднання", handler: {
                _ in
                self.scNameTextField.becomeFirstResponder();
            });
            
            return;
        }
        
        if let connectPort = scPortTextField.text, connectPort.isEmpty {
            showAlert(message: "Не вказано порт підключення", handler: {
                _ in
                self.scPortTextField.becomeFirstResponder();
            });
            
            return;
        }
        
        if let gateAddress = scGateAddressTextField.text, gateAddress.isEmpty {
            showAlert(message: "Не вказано DNS- чи IP- адресу ШЗ", handler: {
                _ in
                self.scGateAddressTextField.becomeFirstResponder();
            });
            
            return;
        }
        
        if let gatePort = scGatePortTextField.text, gatePort.isEmpty {
            showAlert(message: "Не вказано порт ШЗ", handler: {
                _ in
                self.scGatePortTextField.becomeFirstResponder();
            });
            
            return;
        }
        
        let gate = EUSCClientGate.init()
        gate.name = self.scNameTextField.text!;
        gate.connectPort = self.scPortTextField.text!;
        gate.address = self.scGateAddressTextField.text!;
        gate.port = self.scGatePortTextField.text!;
        
        let queue = DispatchQueue(label: "queue")
        queue.async {
            do {
                let isRun = !self.library.scClientIsRunning()
                if (isRun) {
                    try self.library.scClientStart()
                    try self.library.scClientAdd(gate)
                } else {
                    self.library.scClientStop()
                }
                
                DispatchQueue.main.sync {
                    self.scStartButton.titleLabel?.text = isRun ? "Зупинити" : "Запустити"
                    self.scNameTextField.isEnabled = !isRun
                    self.scPortTextField.isEnabled = !isRun
                    self.scGateAddressTextField.isEnabled = !isRun
                    self.scGatePortTextField.isEnabled = !isRun
                }
            } catch {
                NSLog(error.localizedDescription)
                DispatchQueue.main.sync {
                    self.showAlert(message: "Виникла помилка при ініціалізації криптографічної бібліотеки. " +
                        "Опис помилки: " + error.localizedDescription, handler: nil)
                }
            }
        }
    }

	/*
	override func viewWillAppear(_ animated: Bool) {
		super.viewWillAppear(true)
		navigationController?.setNavigationBarHidden(true, animated: true)
	}

	override func viewWillDisappear(_ animated: Bool) {
		super.viewWillDisappear(true)
		navigationController?.setNavigationBarHidden(false, animated: false)
	}
	*/
	
    override func viewDidLoad() {
        super.viewDidLoad()
        
		NotificationCenter.default.addObserver(self, selector: #selector(keyboardWillShow), name: UIResponder.keyboardWillShowNotification, object: nil)
		NotificationCenter.default.addObserver(self, selector: #selector(keyboardWillHide), name: UIResponder.keyboardWillHideNotification, object: nil)
		
        initCryptoLibrary()
        createPickerView()
        dismissPickerView()
    }
        
	@objc func keyboardWillShow(notification: NSNotification) {
		if let keyboardSize = (notification.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? NSValue)?.cgRectValue {
			if self.view.frame.origin.y == 0 {
				self.view.frame.origin.y -= keyboardSize.height
			}
		}
	}

	@objc func keyboardWillHide(notification: NSNotification) {
		if self.view.frame.origin.y != 0 {
			self.view.frame.origin.y = 0
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
    
    func createPickerView() {
        let pickerView = UIPickerView()
        pickerView.delegate = self
        pickerView.dataSource = self
        caTextField.inputView = pickerView
        caTextField.delegate = self
    }

    func dismissPickerView() {
       let toolBar = UIToolbar()
       toolBar.sizeToFit()
       let button = UIBarButtonItem(title: "Обрати", style: .plain, target: self, action: #selector(self.action))
       toolBar.setItems([button], animated: true)
       toolBar.isUserInteractionEnabled = true
       caTextField.inputAccessoryView = toolBar
    }
    
    @objc func action() {
        view.endEditing(true)
    }
    
    func numberOfComponents(in pickerView: UIPickerView) -> Int {
        return 1
    }

    func pickerView(_ pickerView: UIPickerView, numberOfRowsInComponent component: Int) -> Int {
        let CAs = self.library.getCAs()
        return CAs.count
    }

    func pickerView(_ pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String? {
        let CAs = self.library.getCAs()
        return CAs[row].issuerCNs[0]
    }

    func pickerView(_ pickerView: UIPickerView, didSelectRow row: Int, inComponent component: Int) {
        let CAs = self.library.getCAs()
        self.caTextField.text = CAs[row].issuerCNs[0]
        self.view.endEditing(true)
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
            pkReadButton.isEnabled = false
            self.pkFileURI = nil;
            return
        }

        self.pkFileURI = fileURL;
        pkFileTextField.text = fileURL?.absoluteString
        pkPasswordTextField.isEnabled = true
        pkReadButton.isEnabled = true
    }
    
    func initCryptoLibrary() {
        let queue = DispatchQueue(label: "queue")
        queue.async {
            if self.library.isInitialized() {
                return
            }
            
            do {
                let CAsData = try self.readFileFromBundle(fileName: "CAs.json")
                let certificatesData = try self.readFileFromBundle(fileName: "CACertificates.p7b")

                try self.library.initialize(CAsData!, certificates: certificatesData!)
                
                let CAs = self.library.getCAs()
                DispatchQueue.main.sync {
                    self.caTextField.text = CAs.first?.issuerCNs.first
                }
            } catch {
                NSLog(error.localizedDescription)
                DispatchQueue.main.sync {
                    self.showAlert(message: "Виникла помилка при ініціалізації криптографічної бібліотеки. " +
                        "Опис помилки: " + error.localizedDescription, handler: nil)
                }
            }
        }
    }
}
