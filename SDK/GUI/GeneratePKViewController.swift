import UIKit
import MobileCoreServices

struct FileItem {
	var name: String
	var data: Data
}

class GeneratePKViewController: UIViewController, UIPopoverPresentationControllerDelegate, UIDocumentPickerDelegate, UIPickerViewDataSource, UIPickerViewDelegate, UITextFieldDelegate {
	private let library: EUSignCPObjC = EUSignCPObjC.shared()
	private var pkKeyMediaTypes: NSArray?
	private var pkKeyMedias: NSArray?
	private var pkKeyMediaPickerView: UIPickerView?
	
	static let KM_TYPE = "е.ключ ІІТ Алмаз-1К"
	
	@IBOutlet weak var genDSTU4145Switch: UISwitch!
	@IBOutlet weak var genRSASwitch: UISwitch!
	@IBOutlet weak var genECDSASwitch: UISwitch!
	@IBOutlet weak var genFileKeySwitch: UISwitch!
	
	@IBOutlet weak var pkKeyMediaTextField: UITextField!
	@IBOutlet weak var pkKeyMediaSelectButton: UIButton!
	@IBOutlet weak var pkPasswordTextField: UITextField!
	
	@IBOutlet weak var pkGeneratePKeyButton: UIButton!
	
	var actionIndicator: UIActivityIndicatorView!
	
	override func viewDidLoad() {
		super.viewDidLoad()
		
		actionIndicator = UIActivityIndicatorView(frame: view.bounds)
		actionIndicator.center = view.center
		actionIndicator.style = UIActivityIndicatorView.Style.whiteLarge
		actionIndicator.backgroundColor = UIColor(red: 12/255, green: 35/255, blue: 73/255, alpha: 0.5)
		actionIndicator.isUserInteractionEnabled = false
		view.addSubview(actionIndicator)

		updateKeyMedias()
	  
		self.pkKeyMediaPickerView = createPickerViewForTextField(textField: self.pkKeyMediaTextField)
	}

	@IBAction func selectPK(_ sender: Any) {
		let picker = UIDocumentPickerViewController.init(documentTypes: [String(kUTTypeData)], in: .open)
		picker.delegate = self
		self.present(picker, animated: true, completion: nil)
	}
	
	@IBAction func updateKeyMedia(_ sender: Any) {
		updateKeyMedias()
	}
	@IBAction func genFileKeySwitchChanged (_ sender: Any) {
		self.pkPasswordTextField.isEnabled =
			self.pkKeyMedias!.count > 0 ||
			self.genFileKeySwitch.isOn
		self.pkGeneratePKeyButton.isHidden =
			self.pkKeyMedias!.count == 0 &&
			!self.genFileKeySwitch.isOn
	}
	
	@IBAction func generatePK(_ sender: Any) {
		let genDSTU4145 = self.genDSTU4145Switch.isOn
		let genRSA = self.genRSASwitch.isOn
		let genECDSA = self.genECDSASwitch.isOn
		let genFileKey = self.genFileKeySwitch.isOn
		
		var uaKeysType = EUKeysTypeNone
		let uaDSKeysSpec = EUKeysLengthDSUA_257
		let uaKEPKeysSpec = EUKeysLengthKEPUA_431
		var intKeysType = EUKeysTypeNone
		let rsaKeysSpec = EUKeysLengthDSRSA_2048
		let ecdsaKeysSpec = EUKeysLengthDSECDSA_256
		
		var pkData: NSData?
		var requests: NSArray?
		
		if genDSTU4145 {
			uaKeysType.rawValue |= EUKeysTypeDSTUAndECDHWithGOSTs.rawValue
		}
		
		if genRSA {
			intKeysType.rawValue |= EUKeysTypeRSAWithSHA.rawValue
		}
		
		if genECDSA {
			intKeysType.rawValue |= EUKeysTypeECDSAWithSHA.rawValue
		}
		
		let pkKeyMediaName = self.pkKeyMediaTextField.text!
		
		if !genFileKey && pkKeyMediaName.isEmpty {
			showAlert(message: "Не обрано носій з ос. ключем", handler: {
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

		let queue = DispatchQueue(label: "queue")
		queue.async {
			DispatchQueue.main.sync {
				self.actionIndicator.startAnimating()
			}

			do {
				if genFileKey {
					try self.library.generatePrivateKeyBinary(password, uaKeysType: uaKeysType, uaDSKeysSpec: uaDSKeysSpec, uaKEPKeysSpec: uaKEPKeysSpec, intKeysType: intKeysType, rsaKeysSpec: rsaKeysSpec, ecdsaKeysSpec: ecdsaKeysSpec, userInfo: nil, extKeyUsages: nil, privateKey: &pkData, requests: &requests)
				} else {
					let typeIndex = self.pkKeyMediaTypes?.index(of: ReadPKViewController.KM_TYPE)
					let deviceIndex = self.pkKeyMedias?.index(of:pkKeyMediaName)
					
					try self.library.generatePrivateKey( typeIndex!, deviceIndex: deviceIndex!, password: password, setKeyMediaPassword: true, uaKeysType: uaKeysType, uaDSKeysSpec: uaDSKeysSpec, uaKEPKeysSpec: uaKEPKeysSpec, intKeysType: intKeysType, rsaKeysSpec: rsaKeysSpec, ecdsaKeysSpec: ecdsaKeysSpec, userInfo: nil, extKeyUsages: nil, requests: &requests)
				}

				var files = [FileItem]()
				if (genFileKey) {
					files.append(FileItem(name: "Key-6.pfx", data:pkData! as Data))
				}
				
				for request in (requests! as NSArray as! [EURequestInfo]) {
					files.append(FileItem(name: request.name, data:request.data as Data))
				}
				
				self.saveFiles(files: files)
				
				DispatchQueue.main.sync {
					self.showAlert(message: "Особистий ключ успішно згенеровано. " +
						"Для використання ос. ключа необхідно сформувати сертифікати за запитами на формування сертифікатів в ЦСК", handler: nil)
				}
			} catch {
				NSLog(error.localizedDescription)
				DispatchQueue.main.sync {
					self.showAlert(message: "Виникла помилка при генерації ос. ключа. " +
						"Опис помилки: " + error.localizedDescription, handler: nil)
				}
			}

			DispatchQueue.main.sync {
				self.actionIndicator.stopAnimating()
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
		} else {
			return 0
		}
	}

	func pickerView(_ pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String? {
		if pickerView == pkKeyMediaPickerView {
			return pkKeyMedias![row] as? String
		} else {
			return ""
		}
	}

	func pickerView(_ pickerView: UIPickerView, didSelectRow row: Int, inComponent component: Int){
		if pickerView == pkKeyMediaPickerView {
			let keyMedia = pkKeyMedias![row] as? String
			self.pkKeyMediaTextField.text = keyMedia
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
	
	func saveFiles(files: Array<FileItem>) {
		DispatchQueue.main.sync {
			do {
				let tmpDir = FileManager.default.temporaryDirectory
				var filesURLs = [URL]()
				
				for file in files {
					let fileURL = tmpDir.appendingPathComponent(file.name)
					try? FileManager.default.removeItem(at:fileURL)
					try file.data.write(to: fileURL)
					filesURLs.append(fileURL)
				}
				
						
				let activityVC = UIActivityViewController(activityItems: filesURLs, applicationActivities: nil)
				self.present(activityVC, animated: true, completion: nil)
			} catch {
				NSLog(error.localizedDescription)
			}
		}
	}
	
	func updateKeyMedias() {
		let queue = DispatchQueue(label: "queue")
		queue.async {
			DispatchQueue.main.sync {
				self.actionIndicator.startAnimating()
			}
			
			do {
				if self.pkKeyMediaTypes == nil {
					var keyMediaTypes: NSArray? = nil
					
					try self.library.enumKeyMediaTypes(&keyMediaTypes)
				
					self.pkKeyMediaTypes = keyMediaTypes
				}
				
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
						self.genFileKeySwitch.isOn
					self.pkGeneratePKeyButton.isHidden =
						self.pkKeyMedias!.count == 0 &&
						!self.genFileKeySwitch.isOn
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
}

