/*********************************************************************
 * 발주 시스템 보안 가드 (2026-09-09)
 * 목적: 계정 관리 4종(approveUser·rejectUser·deactivateUser·updateUser)을
 *       "승인된 본사 계정" 본인 확인 없이는 실행 불가로 잠근다.
 *
 * 붙여넣는 법 (10분):
 *  1. 발주 구글시트 열기 → 확장 프로그램 → Apps Script
 *  2. 이 파일 전체를 코드 맨 아래에 붙여넣기
 *  3. doPost(e) 함수를 찾아 함수 "첫 줄"에 아래 두 줄 추가:
 *
 *       const g = authGuardE_(e);
 *       if (g) return g;
 *
 *  4. 저장 → 배포 → "배포 관리" → 연필(수정) → 버전: 새 버전 → 배포
 *     ⚠️ "새 배포"를 만들면 주소가 바뀌어 앱이 끊깁니다.
 *        반드시 [배포 관리 → 기존 배포 수정 → 새 버전] 으로!
 *
 * 되돌리기: doPost에 넣은 두 줄만 지우고 다시 새 버전 배포.
 *********************************************************************/

var PROTECTED_ACTIONS_ = ['approveUser', 'rejectUser', 'deactivateUser', 'updateUser'];

function authGuardE_(e) {
  var body = {};
  try { body = JSON.parse(e.postData.contents); } catch (err) { return null; }
  if (PROTECTED_ACTIONS_.indexOf(body.action) === -1) return null; // 보호 대상 아님 → 그대로 진행

  var authId = String(body.authId || '').trim();
  var authPw = String(body.authPw || '');
  if (!authId || !authPw) return deny_('로그인 정보가 없습니다. 앱에서 다시 로그인해 주세요.');

  var sh = findUserSheet_();
  if (!sh) return deny_('[가드설정] 사용자 시트를 찾지 못했습니다.');

  var data = sh.getDataRange().getValues();
  var head = data[0].map(function (h) { return String(h).toLowerCase(); });
  function col(names) {
    for (var i = 0; i < names.length; i++) {
      for (var j = 0; j < head.length; j++) {
        if (head[j].indexOf(names[i]) !== -1) return j;
      }
    }
    return -1;
  }
  var cId = col(['userid', '아이디', 'id']);
  var cPw = col(['password', '비밀번호', '비번', 'pw']);
  var cRole = col(['role', '역할']);
  var cStat = col(['status', '상태']);
  if (cId === -1 || cPw === -1) return deny_('[가드설정] 아이디/비밀번호 컬럼을 찾지 못했습니다.');

  for (var r = 1; r < data.length; r++) {
    if (String(data[r][cId]).trim() === authId) {
      if (!pwMatch_(String(data[r][cPw]), authPw)) return deny_('비밀번호 확인에 실패했습니다. 다시 로그인해 주세요.');
      if (cRole !== -1 && String(data[r][cRole]).trim() !== '본사') return deny_('본사 계정만 사용할 수 있는 기능입니다.');
      if (cStat !== -1 && String(data[r][cStat]).trim() !== '승인') return deny_('사용할 수 없는 계정 상태입니다.');
      return null; // ✅ 본인 확인 통과 → 원래 로직 진행
    }
  }
  return deny_('계정을 찾을 수 없습니다. 다시 로그인해 주세요.');
}

// 비밀번호 저장 방식이 평문이든 SHA-256(hex/base64)이든 맞춰본다
function pwMatch_(stored, given) {
  if (stored === given) return true;
  try {
    var dig = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, given, Utilities.Charset.UTF_8);
    var hex = dig.map(function (b) { return ('0' + (b & 255).toString(16)).slice(-2); }).join('');
    if (stored.toLowerCase() === hex) return true;
    if (stored === Utilities.base64Encode(dig)) return true;
  } catch (err) {}
  return false;
}

function findUserSheet_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var names = ['사용자', 'users', 'Users', '계정', '회원'];
  for (var i = 0; i < names.length; i++) {
    var s = ss.getSheetByName(names[i]);
    if (s) return s;
  }
  var sheets = ss.getSheets();
  for (var k = 0; k < sheets.length; k++) {
    var lc = sheets[k].getLastColumn();
    if (lc < 1) continue;
    var head = sheets[k].getRange(1, 1, 1, lc).getValues()[0].map(function (h) { return String(h).toLowerCase(); });
    for (var j = 0; j < head.length; j++) {
      if (head[j].indexOf('password') !== -1 || head[j].indexOf('비밀번호') !== -1) return sheets[k];
    }
  }
  return null;
}

function deny_(msg) {
  return ContentService.createTextOutput(JSON.stringify({
    success: false, error: 'unauthorized', message: msg
  })).setMimeType(ContentService.MimeType.JSON);
}
