//
//  ViewController.swift
//  KeySafe
//
//  Created by Cristian Sandu on 9/7/15.
//  Copyright © 2015 Cristian Sandu. All rights reserved.
//

import UIKit
import MessageUI
import Foundation
import Security

class ViewController: UIViewController, MFMailComposeViewControllerDelegate {
    @IBOutlet weak var statusLabel: UILabel!
    @IBOutlet weak var pubKeyView: UITextView!
    @IBOutlet weak var signDataView: UITextView!
    
    @IBOutlet weak var cpPubKeyButton: UIButton!
    @IBOutlet weak var emSignDataButton: UIButton!
    @IBOutlet weak var emPubKeyButton: UIButton!
    @IBOutlet weak var cpSignDataButton: UIButton!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }


    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    func mailComposeController(controller: MFMailComposeViewController, didFinishWithResult result: MFMailComposeResult, error: NSError?) {
        controller.dismissViewControllerAnimated(true, completion: nil)
    }

    @IBAction func generateKeyPair(sender: AnyObject) {
        let ret = ECDSA.generateKeyPair(ECDSA.PrivateKeyTag, publicKeyTag: ECDSA.PublicKeyTag)
        
        if (ret.result == errSecSuccess)
        {
            print("PubKey: " + String(ret.publicKey))
            print("PrivKey: " + String(ret.privateKey))

            statusLabel.text = "Status: generated"
            
            let publicKey = ECDSA.getPointCompressedPubKey(ECDSA.PublicKeyTag)
            let rippleAddr = ECDSA.generateRippleAddressFromCompressedPublicKey(publicKey.compressed!)
            
            pubKeyView.text = "\nRipple Address = " + rippleAddr + "\n\n"
            //pubKeyView.text = pubKeyView.text + "Bitcoin Address = " + bitcoinAddr + "\n\n"
            
            pubKeyView.text = pubKeyView.text + "=====\n"
            pubKeyView.text = pubKeyView.text + "ECDSA point compressed hex = " + publicKey.compressed! + "\n\n"
            pubKeyView.text = pubKeyView.text + "ECDSA uncompressed hex = " + publicKey.full! + "\n"
        }
        else
        {
            statusLabel.text = "Status: failed / " + String(ret.result)
        }
    }

    @IBAction func loadKeyPair(sender: AnyObject)
    {
        let ret = ECDSA.loadKeyPair(ECDSA.PrivateKeyTag, publicKeyTag: ECDSA.PublicKeyTag)
        
        print("PubKey: " + String(ret.publicKey))
        print("PrivKey: " + String(ret.privateKey))
    
        if ret.privateKey != nil && ret.publicKey != nil
        {
            statusLabel.text = "Status: loaded"
            
            let publicKey = ECDSA.getPointCompressedPubKey(ECDSA.PublicKeyTag)
            let rippleAddr = ECDSA.generateRippleAddressFromCompressedPublicKey(publicKey.compressed!)
            
            pubKeyView.text = "\nRipple Address = " + rippleAddr + "\n\n"
            //pubKeyView.text = pubKeyView.text + "Bitcoin Address = " + bitcoinAddr + "\n\n"
            
            pubKeyView.text = pubKeyView.text + "=====\n"
            pubKeyView.text = pubKeyView.text + "ECDSA point compressed hex = " + publicKey.compressed! + "\n\n"
            pubKeyView.text = pubKeyView.text + "ECDSA uncompressed hex = " + publicKey.full! + "\n"
         }
        else
        {
            statusLabel.text = "Status: not found"
        }
    }
    
    @IBAction func signData(sender: AnyObject)
    {
        let hash = "56AC80FD38AE8CFFC65CD9AB92C0879DABEE10D3C6FE2CBA6890F8FE4D6B5221"
        
        let (ret, dataHex) = ECDSA.signWithPrivateKey(ECDSA.PrivateKeyTag, hashHex: hash)
        if (ret == errSecSuccess)
        {
            signDataView.text = dataHex!
            
            // Let's verify with OpenSSL the new made signature
            let publicKey = ECDSA.getPointCompressedPubKey(ECDSA.PublicKeyTag)
            
            let result = SecKeyOperations.verifySignature(publicKey.compressed!, signedDataHex: dataHex, hash: hash)
            print("verify = " + String(result))
        }
    }
    
    @IBAction func copyToPasteboard(sender: AnyObject)
    {
        let pasteboard = UIPasteboard.generalPasteboard()
        pasteboard.string = sender as! NSObject == cpPubKeyButton ? pubKeyView.text : signDataView.text
    }

    @IBAction func sendByEmail(sender: AnyObject)
    {
        if (MFMailComposeViewController.canSendMail())
        {
            let isPubKeyButton = sender as! NSObject == emPubKeyButton
            
            let msgText = isPubKeyButton ? pubKeyView.text : signDataView.text
            let msgSbj  = isPubKeyButton ? "Your iPhone ECDSA Public Key" : "Your ECDSA Signed Hash"
            
            let mailView = MFMailComposeViewController()
            mailView.setSubject(msgSbj)
            mailView.setMessageBody(msgText, isHTML: false)
            mailView.mailComposeDelegate = self

            self.presentViewController(mailView, animated: true, completion: nil)

        }
    }
}
