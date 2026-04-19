import urllib.request
import json
import sys
import io

# 出力のエンコーディングをUTF-8に設定
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

class AtlasApiError(Exception):
    """Atlas APIツールの基本例外クラス"""
    pass

class DataNotFoundError(AtlasApiError):
    """指定された検索クエリやIDでデータが見つからない場合の例外"""
    pass

class AtlasApiTool:
    """Atlas Academy APIからデータを取得・検索するためのツールクラス"""
    
    BASE_URL = "https://api.atlasacademy.io"
    
    @staticmethod
    def _fetch_json(endpoint):
        """
        指定されたエンドポイントからJSONデータを取得する
        接続失敗やHTTPエラー(404等)が発生した場合は、呼び出し元へ例外をそのまま投げます。
        """
        url = f"{AtlasApiTool.BASE_URL}/{endpoint}"
        with urllib.request.urlopen(url) as response:
            return json.loads(response.read())

    @staticmethod
    def find_recursive(obj, key_name, search_val):
        """JSONオブジェクト内を再帰的に検索し、一致する要素をリストで返す"""
        results = []
        search_val = str(search_val)
        
        if isinstance(obj, dict):
            if key_name in obj and search_val in str(obj[key_name]):
                results.append(obj)
            for v in obj.values():
                results.extend(AtlasApiTool.find_recursive(v, key_name, search_val))
        elif isinstance(obj, list):
            for item in obj:
                results.extend(AtlasApiTool.find_recursive(item, key_name, search_val))
        return results

    @classmethod
    def search_servant_basic(cls, query):
        """サーヴァントを検索。1件も見つからない場合は DataNotFoundError を投げる"""
        print(f"--- 検索中 (basic_servant): '{query}' ---")
        data = cls._fetch_json("export/JP/basic_servant.json")
        
        results = [s for s in data if query in s['name'] or query in str(s['id'])]
        
        if not results:
            raise DataNotFoundError(f"サーヴァント '{query}' は見つかりませんでした。")
            
        for s in results:
            print(f"ID: {s['id']} | Name: {s['name']} | Class: {s['className']}")
        return results

    @classmethod
    def search_skill_basic(cls, query):
        """スキルを検索。1件も見つからない場合は DataNotFoundError を投げる"""
        print(f"--- 検索中 (basic_skill): '{query}' ---")
        data = cls._fetch_json("export/JP/basic_skill.json")
        
        results = [s for s in data if query in s['name'] or query in str(s['id'])]
        
        if not results:
            raise DataNotFoundError(f"スキル '{query}' は見つかりませんでした。")
            
        for s in results:
            print(f"ID: {s['id']} | Name: {s['name']}")
        return results

    @classmethod
    def get_servant_detail(cls, servant_id):
        """
        特定のサーヴァントの詳細情報を取得。
        IDが存在しない場合は urllib.error.HTTPError (404) 等が発生します。
        """
        print(f"--- 詳細取得 (servant): {servant_id} ---")
        data = cls._fetch_json(f"nice/JP/servant/{servant_id}")
        
        print(f"Name: {data['name']}")
        print("\n[Skills]")
        for sk in data.get('skills', []):
            print(f"- {sk['name']} (ID: {sk['id']})")
            
        print("\n[Noble Phantasms]")
        for np in data.get('noblePhantasms', []):
            print(f"- {np['name']} (ID: {np['id']})")
        
        return data

if __name__ == "__main__":
    # 使用例：例外処理を含めた実装例
    try:
        AtlasApiTool.search_servant_basic("存在しないサーヴァント名")
    except DataNotFoundError as e:
        print(f"通知: {e}")
    except Exception as e:
        print(f"予期せぬエラー: {e}")
