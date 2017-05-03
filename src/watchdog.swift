#!/usr/bin/swift

// Copyright (c) 2017 Torin Kwok

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
//////////////////////////////////////////////////////////////////////

//  watchdog.swift
//  May 3, 2017, v0.1, torin@kwok
//
//  More of a learning experience than a useful product.
//  Ported from a piece of Python script found here:
//  <https://gist.github.com/5a3e7b3631b073db5529722f857f54aa.git> by Todd McDaniel (lazymutt@GitHub).
//  Thank you Todd!
//  Parses update versions, some managed by `sudo softwareupdate --background-critical`
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

/// This is a simple utility function to run an external command
/// synchronously, and return the output, error output as well ass
/// exit code.
func run(
  command cmd: String
, withArguments args: String...
, termination: ( ( Process ) -> Void )? = nil ) -> 
  ( output: [ String ], error: [ String ], exitCode: Int32 ) {

  var output: [ String ] = []
  var error: [ String ] = []

  let subProcess = Process()
  subProcess.launchPath = cmd
  subProcess.arguments = args

  let outPipe = Pipe()
  subProcess.standardOutput = outPipe

  let errPipe = Pipe()
  subProcess.standardError = errPipe

  subProcess.launch()

  let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
  if var stringlized = String( data: outData, encoding: .utf8 ) {
    stringlized = stringlized.trimmingCharacters( in: NSCharacterSet.newlines )
    output = stringlized.components( separatedBy: "\n" )
    }

  let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
  if var stringlized = String( data: errData, encoding: .utf8 ) {
    stringlized = stringlized.trimmingCharacters( in: NSCharacterSet.newlines )
    error = stringlized.components( separatedBy: "\n" )
    }

  if let terminationHandler = termination {
    subProcess.terminationHandler = terminationHandler
    }

  subProcess.waitUntilExit()
  return ( output, error, subProcess.terminationStatus )
  }

//  MARK: Data
//
//////////////////////////////////////////////////////////////////////

/// A bunch of security update items we're going to examine.
enum macOSCriticalUpdateItems: String, EnumCollection {

  case XProtect = "/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"
  case Gatekeeper = "/private/var/db/gkopaque.bundle/Contents/version.plist"
  case SIP = "/System/Library/Sandbox/Compatibility.bundle/Contents/version.plist"
  case MRT = "/System/Library/CoreServices/MRT.app/Contents/version.plist"
  case CoreSuggestions = "/System/Library/Intelligent Suggestions/Assets.suggestionsassets/Contents/version.plist"
  case IncompatibleKernelExt = "/System/Library/Extensions/AppleKextExcludeList.kext/Contents/version.plist"
  case ChineseWordList = "/usr/share/mecabra/updates/com.apple.inputmethod.SCIM.bundle/Contents/version.plist"
  case CoreLSDK = "/usr/share/kdrl.bundle/info.plist"

  var keyInDefaultsSystem: String {
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
    return FileManager.default.fileExists( atPath: self.rawValue )
    }
  }

//  MARK: Get jobs done
//
//////////////////////////////////////////////////////////////////////

do {
  print( "Name", "Date", "Version", separator: String( repeating: " ", count: 10 ) )
  print( String( repeating: "-", count: 42 ) )

  for updateItem in macOSCriticalUpdateItems.allAlternatives() {
    var versionNumber = "N/A"
    var modifiedDate = "N/A"

    guard updateItem.exists else {
      print( updateItem, modifiedDate, versionNumber )
      continue
      }

    let ( output, error, status ) = run(
        command: "/usr/bin/defaults"
      , withArguments: "read", updateItem.rawValue, updateItem.keyInDefaultsSystem 
      )

    let fileAttributes = try? FileManager.default.attributesOfItem( atPath: updateItem.rawValue )
    if let modDate = fileAttributes?[ .modificationDate ] as? Date {
      modifiedDate = modDate.description
      }

    if let version = output.first {
      versionNumber = version
      }

    print( updateItem, modifiedDate, versionNumber )
    }
  }
