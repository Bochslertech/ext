import Principal "mo:base/Principal";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Blob "mo:base/Blob";
import Text "mo:base/Text";
import Array "mo:base/Array";
import Hash "mo:base/Hash";
import Result "mo:base/Result";
import Option "mo:base/Option";

import Hex "mo:crypto/Hex";
import CRC32 "mo:crypto/CRC32";
import SHA224 "mo:crypto/SHA224";
module {
    public type TokenIdentifier = Text;
    public type TokenIndex = Nat32;
    public type Balance = Nat64;
    public type Memo = Blob;
    public type AccountIdentifier = Text;
    public type SubAccount = [Nat8];
    type Result<Ok, Err> = Result.Result<Ok, Err>;
    public type User = {
        // No notification
        #address : AccountIdentifier;
        // defaults to sub account 0
        #principal : Principal;
    };

    public type Metadata = {
        #fungible : {
            name : Text;
            symbol : Text;
            decimals : Nat8;
            metadata : ?Blob;
        };
        #nonfungible : {
            metadata : ?Blob;
        };
    };

    public type MintRequest = {
        to : User;
        metadata : ?Blob;
    };

    public module Core {
        public type Extension = Text;

        public type BalanceRequest = {
            user : User;
            token : TokenIdentifier;
        };

        public type BalanceResponse = Result<Balance, CommonError>;

        public type TransferRequest = {
            from : User;
            to : User;
            token : TokenIdentifier;
            amount : Balance;
            memo : Memo;
            notify : Bool;
            subaccount : ?SubAccount;
        };

        public type TransferResponse = Result<Balance, {
            #Unauthorized : AccountIdentifier;
            #InsufficientBalance;
            // Rejected by canister
            #Rejected;
            #InvalidToken : TokenIdentifier;
            #CannotNotify : AccountIdentifier;
            #Other : Text;
        }>;

        public type CommonError = {
            #InvalidToken : TokenIdentifier;
            #Other : Text;
        };

        public module TokenIndex = {
            type Hash = Hash.Hash;

            public func equal(x : TokenIndex, y : TokenIndex) : Bool {
            return Nat32.equal(x, y);
            };

            public func hash(x : TokenIndex) : Hash {
            return x;
            };
        };
};

    public module TokenIdentifier = {
        // b"\x0Atid"
        private let tds : [Nat8] = [10, 116, 105, 100];

        public let equal = Text.equal;
        public let hash = Text.hash;
        public type TokenObj = {
            index : TokenIndex;
            canister : [Nat8];
        };
        //Coz can't get principal directly, we can compare the bytes
        public func isPrincipal(tid : TokenIdentifier, p : Principal) : Bool {
            let tobj = decode(tid);
            return Blob.equal(Blob.fromArray(tobj.canister), Principal.toBlob(p));
        };

        public func getIndex(tid : TokenIdentifier) : TokenIndex {
            let tobj = decode(tid);
            return tobj.index;
        };

        public func decode(tid : TokenIdentifier) : TokenObj {
            let bytes = Blob.toArray(Principal.toBlob(Principal.fromText(tid)));
            var index : Nat8 = 0;
            var _canister : [Nat8] = [];
            var _token_index : [Nat8] = [];
            var _tdscheck : [Nat8] = [];
            var length : Nat8 = 0;
            for (b in bytes.vals()) {
                length += 1;
                if (length <= 4) {
                _tdscheck := Array.append(_tdscheck, [b]);
                };
                if (length == 4) {
                if (Array.equal(_tdscheck, tds, Nat8.equal) == false) {
                    return {
                    index = 0;
                    canister = bytes;
                    };
                };
                };
            };
            for (b in bytes.vals()) {
                index += 1;
                if (index >= 5) {
                if (index <= (length - 4)) {
                    _canister := Array.append(_canister, [b]);
                } else {
                    _token_index := Array.append(_token_index, [b]);
                };
                };
            };
            let v : TokenObj = {
                index = bytestonat32(_token_index);
                canister = _canister;
            };
            return v;
        };

        private func bytestonat32(b : [Nat8]) : Nat32 {
            var index : Nat32 = 0;
            Array.foldRight<Nat8, Nat32>(b, 0, func (u8, accum) {
                index += 1;
                accum + Nat32.fromNat(Nat8.toNat(u8)) << ((index-1) * 8);
            });
        };

        private func nat32tobytes(n : Nat32) : [Nat8] {
            if (n < 256) {
                return [1, Nat8.fromNat(Nat32.toNat(n))];
            } else if (n < 65536) {
                return [
                2,
                Nat8.fromNat(Nat32.toNat((n >> 8) & 0xFF)),
                Nat8.fromNat(Nat32.toNat((n) & 0xFF))
                ];
            } else if (n < 16777216) {
                return [
                3,
                Nat8.fromNat(Nat32.toNat((n >> 16) & 0xFF)),
                Nat8.fromNat(Nat32.toNat((n >> 8) & 0xFF)),
                Nat8.fromNat(Nat32.toNat((n) & 0xFF))
                ];
            } else {
                return [
                4,
                Nat8.fromNat(Nat32.toNat((n >> 24) & 0xFF)),
                Nat8.fromNat(Nat32.toNat((n >> 16) & 0xFF)),
                Nat8.fromNat(Nat32.toNat((n >> 8) & 0xFF)),
                Nat8.fromNat(Nat32.toNat((n) & 0xFF))
                ];
            };
        };
    };


    public module AccountIdentifier = {

        // b"\x0Aaccount-id"
        private let ads : [Nat8] = [10, 97, 99, 99, 111, 117, 110, 116, 45, 105, 100];

        public let SUBACCOUNT_ZERO : [Nat8] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        public let equal = Text.equal;
        public let hash = Text.hash;

        public func fromText(t : Text, sa : ?SubAccount) : AccountIdentifier {
            return fromPrincipal(Principal.fromText(t), sa);
        };

        public func fromPrincipal(p : Principal, sa : ?SubAccount) : AccountIdentifier {
            return fromBlob(Principal.toBlob(p), sa);
        };

        public func fromBlob(b : Blob, sa : ?SubAccount) : AccountIdentifier {
            return fromBytes(Blob.toArray(b), sa);
        };

        public func fromBytes(data : [Nat8], sa : ?SubAccount) : AccountIdentifier {
            var _sa : [Nat8] = SUBACCOUNT_ZERO;
            if (Option.isSome(sa)) {
            _sa := Option.unwrap(sa);
            };
            var hash : [Nat8] = SHA224.sha224(Array.append(Array.append(ads, data), _sa));
            var crc : [Nat8] = CRC32.crc32(hash);
            return Hex.encode(Array.append(crc, hash));
        };
    };

    public module User = {
        type Hash = Hash.Hash;

        public func toAID(user : User) : AccountIdentifier {
            switch(user) {
                case (#address address) address;
                case (#principal principal) {
                AccountIdentifier.fromPrincipal(principal, null);
                };
            };
        };

        public func toPrincipal(user : User) : ?Principal {
            switch(user) {
                case (#address address) null;
                case (#principal principal) ?principal;
            };
        };

        public func equal(x : User, y : User) : Bool {
            let _x = switch(x) {
                case (#address address) address;
                case (#principal principal) {
                AccountIdentifier.fromPrincipal(principal, null);
                };
            };
            let _y = switch(y) {
                case (#address address) address;
                case (#principal principal) {
                AccountIdentifier.fromPrincipal(principal, null);
                };
            };
            return AccountIdentifier.equal(_x, _y);
        };

        public func hash(x : User) : Hash {
            let _x = switch(x) {
                case (#address address) address;
                case (#principal principal) {
                AccountIdentifier.fromPrincipal(principal, null);
                };
            };
            return AccountIdentifier.hash(_x);
        };
    };

    public module Allowance = {
        public type AllowanceRequest = {
            owner : User;
            spender : Principal;
            token : TokenIdentifier;
        };

        public type ApproveRequest = {
            subaccount : ?SubAccount;
            spender : Principal;
            allowance : Balance;
            token : TokenIdentifier;
        };
    };
}