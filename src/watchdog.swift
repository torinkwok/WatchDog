#!/usr/bin/swift

//  Copyright (c) 2017 Torin Kwok
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//
//////////////////////////////////////////////////////////////////////

//  watchdog.swift
//  May 3, 2017, v0.1, TorinKwok@GitHub
//
//  Ported from a piece of Python script by Todd McDaniel (lazymutt@GitHub) 
//  found here: <https://gist.github.com/5a3e7b3631b073db5529722f857f54aa.git> 
//
//  Thank you Todd!
//
//////////////////////////////////////////////////////////////////////

import Foundation

//  MARK: Utilities
//
//////////////////////////////////////////////////////////////////////

/// A type that can enumerate itself.
/// Adopted by `macOSCriticalUpdateItems` enum in our context.
protocol EnumCollection: Hashable {
  associatedtype CaseType: Hashable = Self
  static func allAlternatives() -> [ CaseType ]
  }

extension EnumCollection {
  /// This utility function heavily relies on several undocumented
  /// Swift compiler behaviors.  So we're using it at our own risk:
  ///
  /// 0.  Memory representation of `enum` - excluding `enum`s with
  ///     associated types - is just a index of cases, when the
  ///     count of the cases is 2...256, it's identical to `UInt8`,
  ///     when 257...65536, it's `UInt16` and so on.  So it can be
  ///     `unsafeBitcast` from corresponding unsigned integer types.
  ///
  /// 1.  `.hashValue` of enum values is the same as the index of
  ///     of the case.
  ///
  /// 2.  `.hashValue` of enum values bitcasted from *invalid* is `0`.
  static func allAlternatives() -> [ CaseType ] {
    let resTypeErasedSeq = AnySequence { () -> AnyIterator<CaseType> in
      var currentIndex = 0

      return AnyIterator {
        let nextIndex = withUnsafeBytes( of: &currentIndex ) {
          $0.load( as: CaseType.self )
          }

        guard nextIndex.hashValue == currentIndex else {
          return nil
          }

        currentIndex += 1
        return nextIndex
        }
      }

    return [ CaseType ]( resTypeErasedSeq )
    }
  }

extension Process {

  enum StandardPipe: EnumCollection { case input; case output; case error }
  typealias PipeDataResolver = () -> [ String ]

  /// This method install a custom pipe for the specified standard I/O 
  /// file and return a closure that directly resolves the installed
  /// pipe's data as an array of `String`, without having to deal with 
  /// `Pipe`s' `fileHandleForReading` method and `FileHandle` class.
  func installPipe( for piptype: StandardPipe ) -> PipeDataResolver {

    let pip = Pipe()
    switch piptype {
      case .input: self.standardInput = pip
      case .output: self.standardOutput = pip
      case .error: self.standardError = pip
      }

    return {
      let outData = pip.fileHandleForReading.readDataToEndOfFile()

      guard var stringlized = String( data: outData, encoding: .utf8 ) else {
        return []
        }

      stringlized = stringlized.trimmingCharacters( in: NSCharacterSet.newlines )
      return stringlized.components( separatedBy: "\n" )
      }
    }

  /// This is a simple utility function to run an external command
  /// synchronously, and return the output, error output as well ass
  /// exit code.
  static func run(
      command cmd: String
    , withArguments args: String...
    , termination: ( ( Process ) -> Void )? = nil ) -> 
    ( output: [ String ], error: [ String ], exitCode: Int32 ) {

    let subProcess = Process()
    subProcess.launchPath = cmd
    subProcess.arguments = args

    let outPipeResolver = subProcess.installPipe( for: .output )
    let errPipeResolver = subProcess.installPipe( for: .error )

    subProcess.launch()

    if let terminationHandler = termination {
      subProcess.terminationHandler = terminationHandler
      }

    subProcess.waitUntilExit()
    return 
      ( outPipeResolver()
      , errPipeResolver()
      , subProcess.terminationStatus 
      )
    }
  }

//  MARK: Data
//
//////////////////////////////////////////////////////////////////////

/// A bunch of security update items we're going to examine.
enum macOSCriticalUpdateItems: String, EnumCollection {

  case XProtect
  case Gatekeeper
  case SIP
  case MRT
  case CoreSuggestions = "Core Suggestions"
  case IncompatibleKernelExt = "Incompatible Kernel Ext."
  case ChineseWordList = "Chinese Word List"
  case CoreLSDK = "Core LSKD (dkrl)"

  var path: String {
    switch self {
      case .XProtect             : return "/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"
      case .Gatekeeper           : return "/private/var/db/gkopaque.bundle/Contents/version.plist"
      case .SIP                  : return "/System/Library/Sandbox/Compatibility.bundle/Contents/version.plist"
      case .MRT                  : return "/System/Library/CoreServices/MRT.app/Contents/version.plist"
      case .CoreSuggestions      : return "/System/Library/Intelligent Suggestions/Assets.suggestionsassets/Contents/version.plist"
      case .IncompatibleKernelExt: return "/System/Library/Extensions/AppleKextExcludeList.kext/Contents/version.plist"
      case .ChineseWordList      : return "/usr/share/mecabra/updates/com.apple.inputmethod.SCIM.bundle/Contents/version.plist"
      case .CoreLSDK             : return "/usr/share/kdrl.bundle/info.plist"
      }
    }

  var versionKeyInDefaultsSystem: String {
    switch self {
      case .XProtect: 
        return "Version"
      case .Gatekeeper, .SIP, .MRT, .CoreSuggestions, .IncompatibleKernelExt:
        return "CFBundleShortVersionString"
      case .ChineseWordList:
        return "SUVersionString"
      case .CoreLSDK:
        return "CFBundleVersion"
      }
    }

  var exists: Bool {
    return FileManager.default.fileExists( atPath: self.path )
    }
  }

//  MARK: Get jobs done
//
//////////////////////////////////////////////////////////////////////

do {
  typealias OutputPrinter = () -> ()

  let assembledPrinter = { 
    ( _ argsTuple: ( first: String, second: Any, third: String )? ) -> OutputPrinter in

    guard let argsTuple = argsTuple else {
      return { print( String( repeating: "-", count: 57 ) ) }
      }

    var dateString: String = ""

    if let date = argsTuple.second as? Date {

      let dateFormatter = DateFormatter()
      dateFormatter.dateStyle = .medium
      dateFormatter.timeStyle = .short

      dateString = dateFormatter.string( from: date )

      } else if let string = argsTuple.second as? String {
        dateString = string
        }

    return { print(
        argsTuple.first.padding( toLength: 24, withPad: " ", startingAt: 0 )
      , dateString.padding( toLength: 24, withPad: " ", startingAt: 0 )
      , argsTuple.third.padding( toLength: 12, withPad: " ", startingAt: 0 )
      ) }
    }

  var outputPrinters: [ OutputPrinter ] = 
    [ assembledPrinter( ( first: "Name", second: "Date", third: "Version" ) )
    , assembledPrinter( nil )
    ]

  for updateItem in macOSCriticalUpdateItems.allAlternatives() 
      where updateItem.exists {

    let ( output, error, _ ) = Process.run(
        command: "/usr/bin/defaults"
      , withArguments: "read", updateItem.path, updateItem.versionKeyInDefaultsSystem 
      )

    if let version = output.first
      , let fileAttributes = try? FileManager.default.attributesOfItem( atPath: updateItem.path )
      , let modDate = fileAttributes[ .modificationDate ] as? Date {

      outputPrinters.append( assembledPrinter( 
        ( first: updateItem.rawValue
        , second: modDate
        , third: version 
        ) ) )
      }
    }

  outputPrinters.forEach { $0() }
  }
