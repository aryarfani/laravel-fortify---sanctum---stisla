<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Validator;
use App\Models\Member;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class MemberController extends Controller
{
    function register(Request $request)
    {
        $this->validate($request, [
            'name' => ['required', 'string'],
            'phone' => [
                'required',
                'unique:members,phone'
            ],
            'password' => ['required', 'string'],
            'address' => ['required', 'string'],
        ]);

        $member =  Member::create([
            'name' => $request['name'],
            'phone' => $request['phone'],
            'address' => $request['address'],
            'password' => Hash::make($request['password']),
        ]);

        return response()->json(['data' => $member]);
    }

    function login(Request $request)
    {
        $member = Member::where('phone', $request->phone)->first();
        if (!$member || !Hash::check($request->password, $member->password)) {
            return response([
                'message' => ['These credentials do not match our records.']
            ], 404);
        }

        $token = $member->createToken('authToken')->plainTextToken;

        $response = [
            'data' => $member,
            'token' => $token
        ];

        return response($response, 200);
    }

    function getCurrentUser(Request $request)
    {
        return response()->json(['data' => $request->user()]);
    }
    function logout(Request $request)
    {
        $request->user()->tokens()->delete();;
        return response('User has successfully logout', 200);
    }
}
