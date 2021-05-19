using System;
using System.Collections.Generic;
using System.Collections;
// using System.Linq;

namespace ConfluencePS
{

	public class Icon {
		public String Path { get; set; }
		public Int64 Width { get; set; }
		public Int64 Height { get; set; }
		public Boolean IsDefault { get; set; }
		public override string ToString() {
			return Path;
		}
	}

	public class User {
		public String UserName { get; set; }
		public String DisplayName { get; set; }
		public String UserKey { get; set; }
		public Icon ProfilePicture { get; set; }
		public override string ToString() {
			return UserName;
		}
	}

	public class Version {
		public User By { get; set; }
		public DateTime When { get; set; }
		public String FriendlyWhen { get; set; }
		public Int64 Number { get; set; }
		public String Message { get; set; }
		public Boolean MinorEdit { get; set; }
		public override string ToString() {
			return Number.ToString();
		}
	}

	public class Space {
		public Int64 Id { get; set; }
		public String Key { get; set; }
		public String Name { get; set; }
		public Icon Icon { get; set; }
		public String Type { get; set; }
		public String Description { get; set; }
		public Page Homepage { get; set; }
		public override string ToString() {
			return "[" + Key + "] " + Name;
		}
	}

	public class Page {
		public Int64 ID { get; set; }
		public String Status { get; set; }
		public String Title { get; set; }
		public Space Space { get; set; }
		public Version Version { get; set; }
		public String Body { get; set; }
		public Page[] Ancestors { get; set; }
		public String URL { get; set; }
		public String ShortURL { get; set; }
		public override string ToString() {
			return "[" + ID + "] " + Title;
		}
	}

	public class Label {
		public Int64 ID { get; set; }
		public String Prefix { get; set; }
		public String Name { get; set; }
		public override string ToString() {
			return Name;
		}
	}

	public class ContentLabelSet {
		public Page Page { get; set; }
		public Label[] Labels { get; set; }
	}

	public class Attachment {
		public Int64 ID { get; set; }
		public String Status { get; set; }
		public String Title { get; set; }
		public String Filename { get; set; }
		public String MediaType { get; set; }
		public UInt64 FileSize { get; set; }
		public String Comment { get; set; }
		public String SpaceKey { get; set; }
		public Int64 PageID { get; set; }
		public Version Version { get; set; }
		public String URL { get; set; }
		public override string ToString() {
			return "[att$ID] $Title";
		}
	}
}
